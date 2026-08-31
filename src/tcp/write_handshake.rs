//! Optional observation of client protocols whose request header is sent by the
//! first application write in sing-box.
//!
//! Shoes writes those headers eagerly while building a proxy chain.  URLTest
//! needs the equivalent boundary without changing normal connection setup, so
//! the final connector can install this task-local observer around its setup.

use std::cell::Cell;
use std::future::Future;

use tokio::time::Instant;

tokio::task_local! {
    static STARTED_AT: Cell<Option<Instant>>;
}

/// Record the first write-handshake boundary in the current observation scope.
///
/// This is deliberately a no-op during ordinary connections and for
/// intermediate hops, where no observation scope is installed.
pub(crate) fn mark_started() {
    let _ = STARTED_AT.try_with(|started_at| {
        if started_at.get().is_none() {
            started_at.set(Some(Instant::now()));
        }
    });
}

/// Run one final-hop setup while observing its first write-handshake boundary.
pub(crate) async fn observe<F>(future: F) -> (F::Output, Option<Instant>)
where
    F: Future,
{
    STARTED_AT
        .scope(Cell::new(None), async move {
            let output = future.await;
            let started_at = STARTED_AT.with(Cell::get);
            (output, started_at)
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn observation_keeps_the_first_marker_and_is_absent_outside_scope() {
        mark_started();

        let (_, started_at) = observe(async {
            tokio::time::advance(std::time::Duration::from_millis(10)).await;
            mark_started();
            tokio::time::advance(std::time::Duration::from_millis(20)).await;
            mark_started();
        })
        .await;

        let started_at = started_at.expect("marker should be observed");
        assert_eq!(Instant::now().duration_since(started_at).as_millis(), 20);
    }
}
