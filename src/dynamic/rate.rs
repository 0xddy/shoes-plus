//! Per-user bandwidth limits.
//!
//! A user's limit is a property of the *user*, not of any one connection: two
//! connections authenticated as the same credential share one bucket, so opening
//! a second connection cannot double the throughput. That is the whole point of
//! a per-user limit, and it is why the buckets live on
//! [`UserContext`](super::UserContext) alongside the byte counters rather than
//! on the stream.
//!
//! # Cancellation-safe admission
//!
//! The bucket never goes into debt. A caller first obtains the bytes that are
//! available now and only then performs its read or write. If the underlying I/O
//! returns `Pending`, errors, or uses fewer bytes than were granted, the unused
//! allowance is returned immediately by [`RatePermit`]. A task waiting for credit
//! owns no reservation, so dropping hundreds of upload streams cannot leave a
//! minutes-long virtual queue behind for the next request.
//!
//! # Why the byte path takes a lock
//!
//! Every other counter in [`UserContext`](super::UserContext) is a relaxed
//! atomic precisely to keep the hot path lock-free, so a mutex here deserves a
//! justification. A token bucket has to read the clock, refill, and subtract as
//! one indivisible step; doing that with atomics costs a CAS loop that is not
//! obviously cheaper than an uncontended mutex, and is considerably easier to
//! get subtly wrong. The mutex is also only ever taken by users who *have* a
//! limit -- [`RateLimiter::poll_acquire`] checks the rate with a relaxed load and
//! returns before touching the lock when the user is unlimited, which is the
//! common case.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::sync::{Notify, futures::OwnedNotified};
use tokio::time::{Instant, Sleep};

/// Smallest burst allowance, in bytes. Matches node-agent's `minBurstSize`.
const MIN_BURST: u64 = 4 * 1024;

/// Largest burst allowance, in bytes. Matches node-agent's `maxBurstSize`.
///
/// Caps how much an idle user can bank and spend at once. Without it a user
/// idle for an hour could open the connection at line rate for as long as their
/// credit lasted, which reads as "the limit is not working".
const MAX_BURST: u64 = 1024 * 1024;

/// Do not turn a saturated stream into one-byte reads. A caller with a smaller
/// buffer still waits only for that buffer; larger callers make progress in at
/// least this quantum once the opening burst has been spent.
const MIN_GRANT: u64 = 4 * 1024;

const BITS_PER_BYTE: u64 = 8;

/// One direction's token bucket.
///
/// `rate_bps` is the authoritative setting and doubles as the "is there a limit
/// at all" flag: `0` means unlimited and is checked before the lock.
#[derive(Debug)]
pub(super) struct RateLimiter {
    rate_bps: AtomicU64,
    state: Mutex<BucketState>,
    changed: Arc<Notify>,
    change_epoch: AtomicU64,
}

#[derive(Debug)]
struct BucketState {
    /// Available credit in bytes. Unlike the old reservation model, this is
    /// always non-negative: future traffic is never charged before it happens.
    tokens: f64,
    /// When `tokens` was last brought up to date.
    last: Option<Instant>,
    /// Invalidates permits granted immediately before a genuine rate change.
    generation: u64,
}

/// Per-stream wait machinery. Waiting owns no shared allowance; this is merely
/// a timer plus a notification that a refund or live rate update made retrying
/// worthwhile before the timer expires.
#[derive(Debug, Default)]
pub(super) struct RateWaiter {
    wait: Option<WaitState>,
}

#[derive(Debug)]
struct WaitState {
    changed_by: Arc<Notify>,
    observed_epoch: u64,
    sleep: Pin<Box<Sleep>>,
    changed: Pin<Box<OwnedNotified>>,
}

/// Allowance removed from the bucket for one synchronous I/O poll.
///
/// `TrafficMeterStream` obtains one, polls the underlying object once, and commits
/// the bytes that actually moved without crossing an `.await`. Datagram admission
/// may retain several permits while assembling an exact jumbo-datagram allowance;
/// cancellation drops that aggregate and returns every unused token.
#[derive(Debug)]
pub(super) struct RatePermit<'a> {
    limiter: Option<&'a RateLimiter>,
    generation: u64,
    granted: u64,
    uncommitted: u64,
}

enum Acquire {
    Unlimited,
    Granted { bytes: u64, generation: u64 },
    Wait { deadline: Instant, epoch: u64 },
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub(super) fn new() -> Self {
        Self {
            rate_bps: AtomicU64::new(0),
            state: Mutex::new(BucketState {
                tokens: 0.0,
                last: None,
                generation: 0,
            }),
            changed: Arc::new(Notify::new()),
            change_epoch: AtomicU64::new(0),
        }
    }

    /// The configured limit in bits per second, or `0` when unlimited.
    #[inline]
    pub(super) fn rate_bps(&self) -> u64 {
        self.rate_bps.load(Ordering::Relaxed)
    }

    /// Sets the limit in bits per second; `0` removes it.
    ///
    /// Re-applying the rate the bucket is already running at is a no-op. This is
    /// what stops a panel that re-sends an unchanged user every minute from
    /// handing out a fresh burst each time. A genuine change resets the bucket
    /// and wakes streams waiting under the old rate.
    pub(super) fn set_rate(&self, rate_bps: u64) {
        if self.rate_bps() == rate_bps {
            return;
        }

        let mut state = self.lock();
        if self.rate_bps() == rate_bps {
            return;
        }
        self.rate_bps.store(rate_bps, Ordering::Relaxed);
        state.tokens = 0.0;
        state.last = None;
        state.generation = state.generation.wrapping_add(1);
        drop(state);
        self.signal_change();
    }

    /// Poll for up to `max_bytes` of allowance.
    ///
    /// Limited callers receive no more than one burst at a time. When less than
    /// [`MIN_GRANT`] is available, larger I/O waits until one useful quantum has
    /// accumulated instead of spinning through tiny reads and writes.
    pub(super) fn poll_acquire<'a>(
        &'a self,
        waiter: &mut RateWaiter,
        cx: &mut Context<'_>,
        max_bytes: u64,
    ) -> Poll<RatePermit<'a>> {
        loop {
            match self.try_acquire(max_bytes) {
                Acquire::Unlimited => {
                    waiter.wait = None;
                    return Poll::Ready(RatePermit::unlimited(max_bytes));
                }
                Acquire::Granted { bytes, generation } => {
                    waiter.wait = None;
                    return Poll::Ready(RatePermit::limited(self, generation, bytes));
                }
                Acquire::Wait { deadline, epoch } => {
                    if waiter
                        .poll_wait(cx, Arc::clone(&self.changed), deadline, epoch, self)
                        .is_pending()
                    {
                        return Poll::Pending;
                    }
                    waiter.wait = None;
                }
            }
        }
    }

    fn try_acquire(&self, max_bytes: u64) -> Acquire {
        if max_bytes == 0 || self.rate_bps() == 0 {
            return Acquire::Unlimited;
        }

        let mut state = self.lock();
        // Take the timestamp only after acquiring the state lock. Otherwise a
        // caller can observe time A, stall on the mutex, and enter after another
        // caller recorded later time B. Recording A after B moves `last` backwards
        // and lets a subsequent caller mint the same elapsed credit twice.
        let now = Instant::now();
        // `set_rate` publishes the atomic while holding this same mutex, so this
        // second read is consistent with the bucket generation and fixes the old
        // relaxed-load-before-lock race.
        let rate_bps = self.rate_bps();
        if rate_bps == 0 {
            return Acquire::Unlimited;
        }

        let bytes_per_second = rate_bps as f64 / BITS_PER_BYTE as f64;
        let burst = burst_for(rate_bps);
        refill(&mut state, now, bytes_per_second, burst as f64);

        let target = max_bytes.min(burst);
        let minimum = target.min(MIN_GRANT);
        let available = state.tokens.floor().max(0.0) as u64;
        if available >= minimum {
            let bytes = available.min(target);
            state.tokens -= bytes as f64;
            return Acquire::Granted {
                bytes,
                generation: state.generation,
            };
        }

        let missing = minimum as f64 - state.tokens;
        let delay =
            Duration::from_secs_f64(missing / bytes_per_second).max(Duration::from_nanos(1));
        Acquire::Wait {
            // Anchor the wake-up to the same instant used for refill. Returning a
            // duration and adding it to a later clock sample after unlocking would
            // under-deliver the configured rate by scheduler/lock latency.
            deadline: now + delay,
            epoch: self.change_epoch.load(Ordering::Acquire),
        }
    }

    fn refund(&self, bytes: u64, generation: u64) {
        if bytes == 0 {
            return;
        }

        let mut state = self.lock();
        let rate_bps = self.rate_bps();
        // A live rate change starts a fresh bucket. Returning allowance granted
        // under the previous generation would create an extra burst.
        if rate_bps == 0 || state.generation != generation {
            return;
        }

        let burst = burst_for(rate_bps) as f64;
        refill(
            &mut state,
            Instant::now(),
            rate_bps as f64 / BITS_PER_BYTE as f64,
            burst,
        );
        state.tokens = (state.tokens + bytes as f64).min(burst);
        drop(state);
        self.signal_change();
    }

    fn signal_change(&self) {
        self.change_epoch.fetch_add(1, Ordering::AcqRel);
        self.changed.notify_waiters();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BucketState> {
        // A panic while holding this lock would otherwise make the user
        // permanently unthrottled or permanently stuck. The state is a plain
        // struct with no invariant that a panic could break mid-update, so
        // recovering it is strictly better than either failure mode.
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl RateWaiter {
    fn poll_wait(
        &mut self,
        cx: &mut Context<'_>,
        changed_by: Arc<Notify>,
        deadline: Instant,
        observed_epoch: u64,
        limiter: &RateLimiter,
    ) -> Poll<()> {
        let replace = self.wait.as_ref().is_none_or(|wait| {
            !Arc::ptr_eq(&wait.changed_by, &changed_by) || wait.observed_epoch != observed_epoch
        });
        if replace {
            let changed = Box::pin(Arc::clone(&changed_by).notified_owned());
            self.wait = Some(WaitState {
                changed_by,
                observed_epoch,
                sleep: Box::pin(tokio::time::sleep_until(deadline)),
                changed,
            });
        } else if let Some(wait) = self.wait.as_mut()
            && deadline < wait.sleep.deadline()
        {
            // A spurious poll must never move an existing wake-up later. The
            // recomputed deadline should normally be identical (elapsed time
            // becomes refilled tokens), but rounding and scheduler jitter are
            // allowed to make it earlier only.
            wait.sleep.as_mut().reset(deadline);
        }

        let wait = self.wait.as_mut().expect("wait state just installed");
        // Register with Notify before checking the epoch. A refund racing between
        // `try_acquire` and this registration is then caught by the epoch check;
        // one racing after it wakes this task normally.
        if wait.changed.as_mut().poll(cx).is_ready()
            || limiter.change_epoch.load(Ordering::Acquire) != observed_epoch
            || wait.sleep.as_mut().poll(cx).is_ready()
        {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl<'a> RatePermit<'a> {
    pub(super) fn unlimited(granted: u64) -> Self {
        Self {
            limiter: None,
            generation: 0,
            granted,
            uncommitted: 0,
        }
    }

    fn limited(limiter: &'a RateLimiter, generation: u64, granted: u64) -> Self {
        Self {
            limiter: Some(limiter),
            generation,
            granted,
            uncommitted: granted,
        }
    }

    #[inline]
    pub(super) fn granted(&self) -> u64 {
        self.granted
    }

    /// Keep `used` bytes charged and immediately return the unused remainder.
    pub(super) fn commit(mut self, used: u64) {
        assert!(used <= self.granted, "I/O exceeded its rate permit");
        let unused = self.uncommitted.saturating_sub(used);
        self.uncommitted = 0;
        if let Some(limiter) = self.limiter {
            limiter.refund(unused, self.generation);
        }
    }
}

impl Drop for RatePermit<'_> {
    fn drop(&mut self) {
        if let Some(limiter) = self.limiter {
            limiter.refund(self.uncommitted, self.generation);
        }
    }
}

fn refill(state: &mut BucketState, now: Instant, bytes_per_second: f64, burst: f64) {
    match state.last {
        None => {
            state.tokens = burst;
            state.last = Some(now);
        }
        Some(last) => {
            // Defensive monotonicity: `try_acquire` samples under the mutex, but
            // retaining the later clock here prevents future callers or tests from
            // reintroducing duplicated refill through an older timestamp.
            let effective_now = now.max(last);
            let elapsed = effective_now.duration_since(last).as_secs_f64();
            state.tokens = (state.tokens + elapsed * bytes_per_second).min(burst);
            state.last = Some(effective_now);
        }
    }
}

/// Burst allowance for a rate, in bytes: one second of traffic, clamped.
///
/// Ported from node-agent's `newByteLimiter`, including its rounding: the
/// bytes-per-second figure is rounded *up* before clamping.
fn burst_for(rate_bps: u64) -> u64 {
    let bytes_per_second = rate_bps.div_ceil(BITS_PER_BYTE);
    bytes_per_second.clamp(MIN_BURST, MAX_BURST)
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;

    use futures::task::noop_waker_ref;

    use super::*;

    /// 8 Mbit/s = 1 MiB/s exactly, which makes the arithmetic below readable.
    const MEBIBYTE_PER_SEC: u64 = 8 * 1024 * 1024;

    async fn consume(limiter: &RateLimiter, mut bytes: u64) {
        let mut waiter = RateWaiter::default();
        while bytes != 0 {
            let permit = poll_fn(|cx| limiter.poll_acquire(&mut waiter, cx, bytes)).await;
            let granted = permit.granted();
            permit.commit(granted);
            bytes -= granted;
        }
    }

    fn consume_now(limiter: &RateLimiter, bytes: u64) {
        let mut waiter = RateWaiter::default();
        let mut cx = Context::from_waker(noop_waker_ref());
        let Poll::Ready(permit) = limiter.poll_acquire(&mut waiter, &mut cx, bytes) else {
            panic!("allowance should be available now");
        };
        assert_eq!(permit.granted(), bytes);
        permit.commit(bytes);
    }

    #[test]
    fn an_unlimited_bucket_never_waits() {
        let limiter = RateLimiter::new();
        consume_now(&limiter, u64::MAX);
    }

    #[test]
    fn burst_matches_the_go_implementation() {
        assert_eq!(burst_for(8), MIN_BURST, "tiny rates get the floor");
        assert_eq!(burst_for(MEBIBYTE_PER_SEC), 1024 * 1024);
        assert_eq!(burst_for(u64::MAX), MAX_BURST, "huge rates get the ceiling");
        // 100 bits/s is 12.5 bytes/s, which must round up, not down.
        assert_eq!(100u64.div_ceil(BITS_PER_BYTE), 13);
    }

    #[tokio::test(start_paused = true)]
    async fn the_first_burst_is_free_and_the_rest_is_paced() {
        let limiter = RateLimiter::new();
        limiter.set_rate(MEBIBYTE_PER_SEC);

        consume_now(&limiter, 1024 * 1024);
        let start = Instant::now();
        consume(&limiter, 1024 * 1024).await;
        assert_eq!(Instant::now().duration_since(start), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn credit_refills_over_time_but_is_capped_at_the_burst() {
        let limiter = RateLimiter::new();
        limiter.set_rate(MEBIBYTE_PER_SEC);
        consume_now(&limiter, 1024 * 1024);

        tokio::time::advance(Duration::from_secs(3600)).await;
        consume_now(&limiter, 1024 * 1024);
        let start = Instant::now();
        consume(&limiter, 1024 * 1024).await;
        assert_eq!(Instant::now().duration_since(start), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_larger_than_the_burst_is_split_and_paced() {
        let limiter = RateLimiter::new();
        limiter.set_rate(MEBIBYTE_PER_SEC);

        let start = Instant::now();
        consume(&limiter, 4 * 1024 * 1024).await;
        assert_eq!(Instant::now().duration_since(start), Duration::from_secs(3));
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_callers_share_one_bucket() {
        let limiter = RateLimiter::new();
        limiter.set_rate(MEBIBYTE_PER_SEC);
        consume_now(&limiter, 1024 * 1024);

        let start = Instant::now();
        tokio::join!(
            consume(&limiter, 1024 * 1024),
            consume(&limiter, 1024 * 1024),
        );
        assert_eq!(Instant::now().duration_since(start), Duration::from_secs(2));
    }

    #[tokio::test(start_paused = true)]
    async fn dropped_waiters_leave_no_debt_for_a_tiny_probe() {
        const RATE_BPS: u64 = 1_000_000;
        const BURST: u64 = 125_000;

        for callers in [8, 32, 256] {
            let limiter = RateLimiter::new();
            limiter.set_rate(RATE_BPS);
            consume_now(&limiter, BURST);

            let mut waiters = Vec::with_capacity(callers);
            let mut cx = Context::from_waker(noop_waker_ref());
            for _ in 0..callers {
                let mut waiter = RateWaiter::default();
                assert!(
                    limiter
                        .poll_acquire(&mut waiter, &mut cx, 32 * 1024)
                        .is_pending()
                );
                waiters.push(waiter);
            }
            drop(waiters);

            let start = Instant::now();
            consume(&limiter, 1024).await;
            let elapsed = Instant::now().duration_since(start);
            let ideal = Duration::from_micros(8192);
            assert!(
                (ideal..=ideal + Duration::from_millis(1)).contains(&elapsed),
                "{callers} canceled streams delayed the probe by {elapsed:?}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn spurious_polls_do_not_push_a_waiters_deadline_back() {
        let limiter = RateLimiter::new();
        let changed_by = Arc::clone(&limiter.changed);
        let observed_epoch = limiter.change_epoch.load(Ordering::Acquire);
        let mut waiter = RateWaiter::default();
        let mut cx = Context::from_waker(noop_waker_ref());
        let delay = Duration::from_millis(100);
        let original_deadline = Instant::now() + delay;

        assert!(
            waiter
                .poll_wait(
                    &mut cx,
                    Arc::clone(&changed_by),
                    original_deadline,
                    observed_epoch,
                    &limiter,
                )
                .is_pending()
        );
        assert_eq!(
            waiter.wait.as_ref().unwrap().sleep.deadline(),
            original_deadline
        );

        // Model unrelated I/O repeatedly waking the same task. Each new target
        // is 100 ms from *that* poll and therefore later than the one already
        // armed; replacing it would make a busy connection wait forever.
        for _ in 0..5 {
            tokio::time::advance(Duration::from_millis(10)).await;
            assert!(
                waiter
                    .poll_wait(
                        &mut cx,
                        Arc::clone(&changed_by),
                        Instant::now() + delay,
                        observed_epoch,
                        &limiter,
                    )
                    .is_pending()
            );
            assert_eq!(
                waiter.wait.as_ref().unwrap().sleep.deadline(),
                original_deadline
            );
        }

        tokio::time::advance(Duration::from_millis(50)).await;
        assert!(
            waiter
                .poll_wait(
                    &mut cx,
                    changed_by,
                    Instant::now() + delay,
                    observed_epoch,
                    &limiter,
                )
                .is_ready(),
            "the original 100 ms deadline must still fire"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn wait_deadline_is_anchored_to_the_refill_observation() {
        const RATE_BPS: u64 = 1_000_000;
        const BURST: u64 = 125_000;

        let limiter = RateLimiter::new();
        limiter.set_rate(RATE_BPS);
        consume_now(&limiter, BURST);
        let observed_at = Instant::now();
        let Acquire::Wait { deadline, epoch } = limiter.try_acquire(4096) else {
            panic!("an empty bucket must wait");
        };
        assert_eq!(deadline, observed_at + Duration::from_micros(32_768));

        // Simulate the task being descheduled after releasing the bucket lock.
        // Installing the timer later must retain the deadline computed above.
        tokio::time::advance(Duration::from_millis(10)).await;
        let mut waiter = RateWaiter::default();
        let mut cx = Context::from_waker(noop_waker_ref());
        assert!(
            waiter
                .poll_wait(
                    &mut cx,
                    Arc::clone(&limiter.changed),
                    deadline,
                    epoch,
                    &limiter,
                )
                .is_pending()
        );
        assert_eq!(waiter.wait.as_ref().unwrap().sleep.deadline(), deadline);
    }

    #[tokio::test(start_paused = true)]
    async fn refill_never_moves_its_clock_backwards() {
        let base = Instant::now();
        let later = base + Duration::from_millis(100);
        let mut state = BucketState {
            tokens: 0.0,
            last: Some(later),
            generation: 0,
        };

        refill(
            &mut state,
            base + Duration::from_millis(50),
            1000.0,
            10_000.0,
        );
        assert_eq!(state.last, Some(later));
        assert_eq!(state.tokens, 0.0);

        refill(
            &mut state,
            base + Duration::from_millis(150),
            1000.0,
            10_000.0,
        );
        assert_eq!(state.last, Some(base + Duration::from_millis(150)));
        assert_eq!(state.tokens, 50.0, "only the new 50 ms may be refilled");
    }

    #[test]
    fn concurrent_acquisitions_share_one_opening_burst() {
        let limiter = Arc::new(RateLimiter::new());
        limiter.set_rate(8); // one byte per second, with the 4 KiB burst floor
        let barrier = Arc::new(std::sync::Barrier::new(33));
        let mut callers = Vec::new();
        for _ in 0..32 {
            let limiter = Arc::clone(&limiter);
            let barrier = Arc::clone(&barrier);
            callers.push(std::thread::spawn(move || {
                barrier.wait();
                match limiter.try_acquire(MIN_BURST) {
                    Acquire::Granted { bytes, .. } => bytes,
                    Acquire::Wait { .. } => 0,
                    Acquire::Unlimited => panic!("the limiter is enabled"),
                }
            }));
        }
        barrier.wait();

        let granted: u64 = callers
            .into_iter()
            .map(|caller| caller.join().expect("caller must not panic"))
            .sum();
        assert_eq!(granted, MIN_BURST);
    }

    #[tokio::test(start_paused = true)]
    async fn an_unused_permit_is_returned() {
        let limiter = RateLimiter::new();
        limiter.set_rate(MEBIBYTE_PER_SEC);

        let mut waiter = RateWaiter::default();
        let mut cx = Context::from_waker(noop_waker_ref());
        let Poll::Ready(permit) = limiter.poll_acquire(&mut waiter, &mut cx, 1024 * 1024) else {
            panic!("opening burst should be available");
        };
        drop(permit);
        consume_now(&limiter, 1024 * 1024);
    }

    #[tokio::test(start_paused = true)]
    async fn re_applying_the_same_rate_does_not_hand_out_a_fresh_burst() {
        let limiter = RateLimiter::new();
        limiter.set_rate(MEBIBYTE_PER_SEC);
        consume_now(&limiter, 1024 * 1024);

        for _ in 0..10 {
            limiter.set_rate(MEBIBYTE_PER_SEC);
        }
        let start = Instant::now();
        consume(&limiter, 1024 * 1024).await;
        assert_eq!(Instant::now().duration_since(start), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_genuine_rate_change_resets_the_bucket() {
        let limiter = RateLimiter::new();
        limiter.set_rate(MEBIBYTE_PER_SEC);
        consume_now(&limiter, 1024 * 1024);

        limiter.set_rate(MEBIBYTE_PER_SEC * 4);
        consume_now(&limiter, 1024 * 1024);
    }

    #[tokio::test(start_paused = true)]
    async fn removing_the_limit_wakes_an_existing_waiter() {
        let limiter = RateLimiter::new();
        limiter.set_rate(MEBIBYTE_PER_SEC);
        consume_now(&limiter, 1024 * 1024);

        let mut waiter = RateWaiter::default();
        let wait = poll_fn(|cx| limiter.poll_acquire(&mut waiter, cx, 64 * 1024 * 1024));
        tokio::pin!(wait);
        assert!(futures::poll!(wait.as_mut()).is_pending());
        limiter.set_rate(0);
        let permit = wait.await;
        assert_eq!(permit.granted(), 64 * 1024 * 1024);
        permit.commit(64 * 1024 * 1024);
    }

    #[tokio::test(start_paused = true)]
    async fn sustained_throughput_converges_on_the_configured_rate() {
        let limiter = RateLimiter::new();
        limiter.set_rate(MEBIBYTE_PER_SEC);
        consume_now(&limiter, 1024 * 1024);

        let start = Instant::now();
        for _ in 0..128 {
            consume(&limiter, 64 * 1024).await;
        }
        assert_eq!(
            Instant::now().duration_since(start),
            Duration::from_secs(8),
            "8 MiB after the burst must drain at one MiB/s"
        );
    }
}
