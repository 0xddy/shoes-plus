// Forked from tokio's copy.rs and copy_bidirectional.rs.
//
// Changes:
// - Customizable buffer size
// - Don't bother initializing buffer
// - Read and write whenever there's a space
// - Circular buffer
// - Cooperative yielding via tokio's coop budget to prevent task starvation

use futures::ready;
use tokio::io::ReadBuf;

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::async_stream::AsyncStream;
use crate::util::allocate_vec;

const DEFAULT_BUF_SIZE: usize = 16384;

#[derive(Debug)]
struct CopyBuffer {
    read_done: bool,
    need_flush: bool,
    need_write_ping: bool,
    start_index: usize,
    cache_length: usize,
    size: usize,
    buf: Box<[u8]>,
}

impl CopyBuffer {
    pub fn new(size: usize, need_initial_flush: bool) -> Self {
        let buf = allocate_vec(size);
        Self {
            read_done: false,
            need_flush: need_initial_flush,
            need_write_ping: false,
            start_index: 0,
            cache_length: 0,
            size,
            buf: buf.into_boxed_slice(),
        }
    }

    pub fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncStream + ?Sized,
        W: AsyncStream + ?Sized,
    {
        loop {
            let mut read_pending = false;
            let mut write_pending = false;

            // Read as much as possible before writing. Some AsyncStream implementations
            // packetize each poll_write call individually, so this reduces the overhead.
            // Other AsyncStream implementations cache on poll_write, and
            // packetize/write to the stream on poll_flush - and this also ends up being
            // beneficial since we are calling poll_flush each external loop iteration.
            while !self.read_done && self.cache_length < self.size {
                // Charge each I/O operation, including partially ready buffered
                // streams. One guard around the whole loop only spends one unit
                // and cannot prevent a hot relay from monopolizing its worker.
                let coop = ready!(tokio::task::coop::poll_proceed(cx));
                let unused_start_index = (self.start_index + self.cache_length) % self.size;
                let unused_end_index_exclusive = if unused_start_index < self.start_index {
                    self.start_index
                } else {
                    self.size
                };

                let me = &mut *self;
                let mut buf =
                    ReadBuf::new(&mut me.buf[unused_start_index..unused_end_index_exclusive]);
                match reader.as_mut().poll_read(cx, &mut buf) {
                    Poll::Ready(val) => {
                        val?;
                        coop.made_progress();
                        let n = buf.filled().len();
                        if n == 0 {
                            self.read_done = true;
                        } else {
                            self.cache_length += n;
                        }
                    }
                    Poll::Pending => {
                        read_pending = true;
                        break;
                    }
                }
            }

            if self.need_write_ping {
                // if we just read data and we are going to write anyway, no need for a ping
                if self.cache_length == 0 {
                    let coop = ready!(tokio::task::coop::poll_proceed(cx));
                    match writer.as_mut().poll_write_ping(cx) {
                        Poll::Ready(val) => {
                            let written = val?;
                            coop.made_progress();
                            self.need_write_ping = false;
                            if written {
                                self.need_flush = true;
                            }
                        }
                        Poll::Pending => {
                            write_pending = true;
                        }
                    }
                } else {
                    self.need_write_ping = false;
                }
            }

            // If our buffer has some data, let's write it out!
            // Loop and try to write out as much as possible to minimize forwarding
            // latency, and so that we increase the chance we have an optimal read
            // with start_index at zero.
            while self.cache_length > 0 {
                let coop = ready!(tokio::task::coop::poll_proceed(cx));
                let used_start_index = self.start_index;
                let used_end_index_exclusive =
                    std::cmp::min(self.start_index + self.cache_length, self.size);

                let me = &mut *self;
                match writer
                    .as_mut()
                    .poll_write(cx, &me.buf[used_start_index..used_end_index_exclusive])
                {
                    Poll::Ready(val) => {
                        let written = val?;
                        if written == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "write zero byte into writer",
                            )));
                        } else {
                            self.cache_length -= written;
                            if self.cache_length == 0 {
                                self.start_index = 0;
                            } else {
                                self.start_index = (self.start_index + written) % self.size;
                            }
                            self.need_flush = true;
                            coop.made_progress();
                        }
                    }
                    Poll::Pending => {
                        write_pending = true;
                        break;
                    }
                }
            }

            if self.need_flush {
                let coop = ready!(tokio::task::coop::poll_proceed(cx));
                ready!(writer.as_mut().poll_flush(cx))?;
                self.need_flush = false;
                coop.made_progress();
            }

            // If we've written all the data and we've seen EOF, finish the transfer.
            if self.read_done && self.cache_length == 0 {
                return Poll::Ready(Ok(()));
            }

            // Return Pending to prevent task starvation
            if read_pending || write_pending {
                return Poll::Pending;
            }
        }
    }
}

enum TransferState {
    Running,
    ShuttingDown,
    Done,
}

struct CopyBidirectional<'a, A: ?Sized, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
    a_buf: CopyBuffer,
    b_buf: CopyBuffer,
    a_to_b: TransferState,
    b_to_a: TransferState,
    poll_b_first: bool,
    sleep_future: Option<Pin<Box<tokio::time::Sleep>>>,
}

fn transfer_one_direction<A, B>(
    cx: &mut Context<'_>,
    state: &mut TransferState,
    buf: &mut CopyBuffer,
    r: &mut A,
    w: &mut B,
) -> Poll<io::Result<()>>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    let mut r = Pin::new(r);
    let mut w = Pin::new(w);

    loop {
        match state {
            TransferState::Running => {
                ready!(buf.poll_copy(cx, r.as_mut(), w.as_mut()))?;
                *state = TransferState::ShuttingDown;
            }
            TransferState::ShuttingDown => {
                ready!(w.as_mut().poll_shutdown(cx))?;
                *state = TransferState::Done;
            }
            TransferState::Done => return Poll::Ready(Ok(())),
        }
    }
}

impl<A, B> Future for CopyBidirectional<'_, A, B>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let CopyBidirectional {
            a,
            b,
            a_buf,
            b_buf,
            a_to_b,
            b_to_a,
            poll_b_first,
            sleep_future,
        } = &mut *self;

        if let Some(sleep) = sleep_future {
            let ping_fired = sleep.as_mut().poll(cx).is_ready();
            if ping_fired {
                // a_buf writes to b - so we need to check if b supports ping, and similarly
                // for b_buf.
                a_buf.need_write_ping = b.supports_ping();
                b_buf.need_write_ping = a.supports_ping();
                sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + std::time::Duration::from_secs(60));
            }
        }

        // Both directions share the task's cooperative budget. Rotate which one
        // polls first so a continuously ready upload cannot spend every turn's
        // budget before the reverse stream gets a chance to run.
        let (a_to_b, b_to_a) = if *poll_b_first {
            let b_result = transfer_one_direction(cx, b_to_a, &mut *b_buf, &mut *b, &mut *a);
            let a_result = transfer_one_direction(cx, a_to_b, &mut *a_buf, &mut *a, &mut *b);
            (a_result, b_result)
        } else {
            let a_result = transfer_one_direction(cx, a_to_b, &mut *a_buf, &mut *a, &mut *b);
            let b_result = transfer_one_direction(cx, b_to_a, &mut *b_buf, &mut *b, &mut *a);
            (a_result, b_result)
        };
        *poll_b_first = !*poll_b_first;

        match (a_to_b, b_to_a) {
            (Poll::Ready(Err(e)), _) | (_, Poll::Ready(Err(e))) => Poll::Ready(Err(e)),
            (Poll::Ready(Ok(())), Poll::Ready(Ok(()))) => Poll::Ready(Ok(())),
            _ => Poll::Pending,
        }
    }
}

/// Copies data in both directions between `a` and `b`.
///
/// This function returns a future that will read from both streams,
/// writing any data read to the opposing stream.
/// This happens in both directions concurrently.
///
/// If an EOF is observed on one stream, [`shutdown()`] will be invoked on
/// the other, and reading from that stream will stop. Copying of data in
/// the other direction will continue.
///
/// The future will complete successfully once both directions of communication has been shut down.
/// A direction is shut down when the reader reports EOF,
/// at which point [`shutdown()`] is called on the corresponding writer. When finished,
/// it will return a tuple of the number of bytes copied from a to b
/// and the number of bytes copied from b to a, in that order.
///
/// [`shutdown()`]: crate::io::AsyncWriteExt::shutdown
///
/// # Errors
///
/// The future will immediately return an error if any IO operation on `a`
/// or `b` returns an error. Some data read from either stream may be lost (not
/// written to the other stream) in this case.
///
/// # Return value
///
/// Returns a tuple of bytes copied `a` to `b` and bytes copied `b` to `a`.
pub async fn copy_bidirectional<A, B>(
    a: &mut A,
    b: &mut B,
    a_need_initial_flush: bool,
    b_need_initial_flush: bool,
) -> io::Result<()>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    copy_bidirectional_with_sizes(
        a,
        b,
        a_need_initial_flush,
        b_need_initial_flush,
        DEFAULT_BUF_SIZE,
        DEFAULT_BUF_SIZE,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_stream::AsyncPing;
    use std::future::poll_fn;
    use tokio::io::{AsyncRead, AsyncWrite};

    // Buffered wrappers and Quinn can return Ready without spending Tokio's I/O
    // budget. The forwarding loop must also cooperate on those paths.
    struct ReadyStream {
        input: Vec<u8>,
        offset: usize,
        output: Vec<u8>,
        read_chunk: usize,
        write_chunk: usize,
    }

    impl ReadyStream {
        fn new(input: Vec<u8>, read_chunk: usize, write_chunk: usize) -> Self {
            Self {
                input,
                offset: 0,
                output: Vec::new(),
                read_chunk,
                write_chunk,
            }
        }
    }

    impl AsyncRead for ReadyStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let n = buf
                .remaining()
                .min(self.read_chunk)
                .min(self.input.len() - self.offset);
            buf.put_slice(&self.input[self.offset..self.offset + n]);
            self.offset += n;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ReadyStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let n = buf.len().min(self.write_chunk);
            self.output.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for ReadyStream {
        fn supports_ping(&self) -> bool {
            false
        }
        fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }
    impl AsyncStream for ReadyStream {}

    async fn check_yield_and_resume(read_chunk: usize, write_chunk: usize, buffer_size: usize) {
        let expected: Vec<u8> = (0..65536).map(|n| (n % 251) as u8).collect();
        let mut reader = ReadyStream::new(expected.clone(), read_chunk, usize::MAX);
        let mut writer = ReadyStream::new(Vec::new(), usize::MAX, write_chunk);
        let mut buffer = CopyBuffer::new(buffer_size, false);
        let yielded = poll_fn(|cx| {
            Poll::Ready(
                buffer
                    .poll_copy(cx, Pin::new(&mut reader), Pin::new(&mut writer))
                    .is_pending(),
            )
        })
        .await;
        assert!(
            yielded,
            "hot buffered I/O must return to the scheduler before EOF"
        );
        assert!(writer.output.len() < expected.len());
        poll_fn(|cx| buffer.poll_copy(cx, Pin::new(&mut reader), Pin::new(&mut writer)))
            .await
            .unwrap();
        assert_eq!(
            writer.output, expected,
            "yielding must preserve all buffered bytes"
        );
    }

    #[tokio::test]
    async fn hot_copy_cooperates_between_batches() {
        check_yield_and_resume(256, 256, 256).await;
    }

    #[tokio::test]
    async fn hot_copy_cooperates_during_partial_reads() {
        check_yield_and_resume(1, usize::MAX, 16384).await;
    }

    #[tokio::test]
    async fn hot_copy_cooperates_during_partial_writes() {
        check_yield_and_resume(usize::MAX, 1, 16384).await;
    }

    #[tokio::test]
    async fn hot_upload_does_not_starve_the_reverse_direction() {
        let upload = vec![b'u'; 1024 * 1024];
        let reply = b"reverse response".to_vec();
        let mut client = ReadyStream::new(upload.clone(), 1, usize::MAX);
        let mut destination = ReadyStream::new(reply.clone(), usize::MAX, usize::MAX);
        let mut copy = CopyBidirectional {
            a: &mut client,
            b: &mut destination,
            a_buf: CopyBuffer::new(16384, false),
            b_buf: CopyBuffer::new(16384, false),
            a_to_b: TransferState::Running,
            b_to_a: TransferState::Running,
            poll_b_first: false,
            sleep_future: None,
        };
        // Give the relay fresh scheduler turns. A permanently preferred hot
        // direction would spend every turn's shared budget before the reply.
        for _ in 0..3 {
            tokio::task::yield_now().await;
            poll_fn(|cx| {
                let _ = Pin::new(&mut copy).poll(cx);
                Poll::Ready(())
            })
            .await;
        }
        assert_eq!(copy.a.output, reply);
        assert!(
            copy.b.output.len() < upload.len(),
            "the reply must be forwarded during the upload"
        );
        copy.await.unwrap();
        assert_eq!(destination.output, upload);
    }
}

/// Copies data in both directions between `a` and `b` using buffers of the specified size.
///
/// This method is the same as the [`copy_bidirectional()`], except that it allows you to set the
/// size of the internal buffers used when copying data.
pub async fn copy_bidirectional_with_sizes<A, B>(
    a: &mut A,
    b: &mut B,
    a_need_initial_flush: bool,
    b_need_initial_flush: bool,
    a_to_b_buf_size: usize,
    b_to_a_buf_size: usize,
) -> io::Result<()>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    let sleep_future = if a.supports_ping() || b.supports_ping() {
        Some(Box::pin(tokio::time::sleep(
            std::time::Duration::from_secs(60),
        )))
    } else {
        None
    };

    CopyBidirectional {
        a,
        b,
        // this is correctly reversed - CopyBuffer will copy from a (reader) to b (writer) using
        // a_buf, which means that the need_flush signal is for the writer (b), and vice versa for
        // b_buf.
        a_buf: CopyBuffer::new(a_to_b_buf_size, b_need_initial_flush),
        b_buf: CopyBuffer::new(b_to_a_buf_size, a_need_initial_flush),
        a_to_b: TransferState::Running,
        b_to_a: TransferState::Running,
        poll_b_first: false,
        sleep_future,
    }
    .await
}
