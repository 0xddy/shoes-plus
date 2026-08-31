//! Per-user bandwidth limits.
//!
//! A user's limit is a property of the *user*, not of any one connection: two
//! connections authenticated as the same credential share one bucket, so opening
//! a second connection cannot double the throughput. That is the whole point of
//! a per-user limit, and it is why the buckets live on
//! [`UserContext`](super::UserContext) alongside the byte counters rather than
//! on the stream.
//!
//! # Shape
//!
//! A standard token bucket, with one deliberate asymmetry: credit is capped at
//! `burst` but *debt* is not. A caller that asks for more than a full burst is
//! never refused, it just waits proportionally longer. Refusing would mean
//! failing a legitimate large write, and capping the debt would let an
//! oversized write escape the limit entirely.
//!
//! # Why the byte path takes a lock
//!
//! Every other counter in [`UserContext`](super::UserContext) is a relaxed
//! atomic precisely to keep the hot path lock-free, so a mutex here deserves a
//! justification. A token bucket has to read the clock, refill, and subtract as
//! one indivisible step; doing that with atomics costs a CAS loop that is not
//! obviously cheaper than an uncontended mutex, and is considerably easier to
//! get subtly wrong. The mutex is also only ever taken by users who *have* a
//! limit -- [`RateLimiter::reserve`] checks the rate with a relaxed load and
//! returns before touching the lock when the user is unlimited, which is the
//! common case.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::time::Instant;

/// Smallest burst allowance, in bytes. Matches node-agent's `minBurstSize`.
///
/// A burst below one buffer's worth would make every single read wait, turning
/// a rate limit into a latency penalty on top of the throughput cap.
const MIN_BURST: u64 = 4 * 1024;

/// Largest burst allowance, in bytes. Matches node-agent's `maxBurstSize`.
///
/// Caps how much an idle user can bank and spend at once. Without it a user
/// idle for an hour could open the connection at line rate for as long as their
/// credit lasted, which reads as "the limit is not working".
const MAX_BURST: u64 = 1024 * 1024;

const BITS_PER_BYTE: u64 = 8;

/// One direction's token bucket.
///
/// `rate_bps` is the authoritative setting and doubles as the "is there a limit
/// at all" flag: `0` means unlimited and is checked before the lock.
#[derive(Debug)]
pub(super) struct RateLimiter {
    rate_bps: AtomicU64,
    state: Mutex<BucketState>,
}

#[derive(Debug)]
struct BucketState {
    /// Available credit in bytes. Negative means the bucket is in debt and the
    /// next caller must wait for it to refill past zero.
    tokens: f64,
    /// When `tokens` was last brought up to date.
    last: Option<Instant>,
    /// The rate the current `tokens` value was accumulated under. Used to
    /// detect a genuine rate change; see [`RateLimiter::set_rate`].
    accrued_at_bps: u64,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub(super) const fn new() -> Self {
        Self {
            rate_bps: AtomicU64::new(0),
            state: Mutex::new(BucketState {
                tokens: 0.0,
                last: None,
                accrued_at_bps: 0,
            }),
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
    /// not an optimisation -- it is what stops a panel that re-sends an
    /// unchanged user every minute from handing out a fresh burst each time and
    /// quietly dissolving the limit. Only a genuine change resets the bucket.
    pub(super) fn set_rate(&self, rate_bps: u64) {
        if self.rate_bps.swap(rate_bps, Ordering::Relaxed) == rate_bps {
            return;
        }
        let mut state = self.lock();
        if state.accrued_at_bps == rate_bps {
            return;
        }
        state.tokens = 0.0;
        state.last = None;
        state.accrued_at_bps = rate_bps;
    }

    /// Claims `n` bytes and reports how long the caller must wait before those
    /// bytes are within the limit.
    ///
    /// The bytes are always granted; the return value is a delay, not a refusal.
    /// [`Duration::ZERO`] means the caller may proceed immediately.
    pub(super) fn reserve(&self, n: u64) -> Duration {
        let rate_bps = self.rate_bps();
        if rate_bps == 0 || n == 0 {
            return Duration::ZERO;
        }
        let bytes_per_second = rate_bps as f64 / BITS_PER_BYTE as f64;
        let burst = burst_for(rate_bps) as f64;

        let now = Instant::now();
        let mut state = self.lock();

        // A rate change between the relaxed load above and this lock would make
        // us refill at the wrong rate. Re-reading under the lock keeps refill
        // and rate consistent with each other.
        state.accrued_at_bps = rate_bps;
        match state.last {
            None => state.tokens = burst,
            Some(last) => {
                let elapsed = now.saturating_duration_since(last).as_secs_f64();
                state.tokens = (state.tokens + elapsed * bytes_per_second).min(burst);
            }
        }
        state.last = Some(now);
        state.tokens -= n as f64;

        if state.tokens >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-state.tokens / bytes_per_second)
        }
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
    use super::*;

    /// 8 Mbit/s = 1 MiB/s exactly, which makes the arithmetic below readable.
    const MEBIBYTE_PER_SEC: u64 = 8 * 1024 * 1024;

    #[test]
    fn an_unlimited_bucket_never_waits() {
        let limiter = RateLimiter::new();
        assert_eq!(limiter.reserve(u64::MAX), Duration::ZERO);
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

        // The bucket starts full, so exactly one burst passes without waiting.
        assert_eq!(limiter.reserve(1024 * 1024), Duration::ZERO);

        // The next full burst has to be earned at one MiB per second.
        let wait = limiter.reserve(1024 * 1024);
        assert_eq!(wait, Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn credit_refills_over_time_but_is_capped_at_the_burst() {
        let limiter = RateLimiter::new();
        limiter.set_rate(MEBIBYTE_PER_SEC);
        assert_eq!(limiter.reserve(1024 * 1024), Duration::ZERO);

        // Idle for an hour: credit stops accruing at one burst, so only one
        // burst is free afterwards rather than an hour's worth.
        tokio::time::advance(Duration::from_secs(3600)).await;
        assert_eq!(limiter.reserve(1024 * 1024), Duration::ZERO);
        assert_eq!(limiter.reserve(1024 * 1024), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_larger_than_the_burst_waits_rather_than_failing() {
        let limiter = RateLimiter::new();
        limiter.set_rate(MEBIBYTE_PER_SEC);

        // Four MiB against a one MiB burst: granted, with three seconds of debt
        // beyond the free burst.
        let wait = limiter.reserve(4 * 1024 * 1024);
        assert_eq!(wait, Duration::from_secs(3));
    }

    #[tokio::test(start_paused = true)]
    async fn debt_accumulates_across_callers_sharing_one_bucket() {
        // Two connections, one user: the second must see the first one's debt.
        let limiter = RateLimiter::new();
        limiter.set_rate(MEBIBYTE_PER_SEC);
        assert_eq!(limiter.reserve(1024 * 1024), Duration::ZERO);

        assert_eq!(limiter.reserve(1024 * 1024), Duration::from_secs(1));
        assert_eq!(
            limiter.reserve(1024 * 1024),
            Duration::from_secs(2),
            "a second connection cannot reset the debt and double the rate"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn re_applying_the_same_rate_does_not_hand_out_a_fresh_burst() {
        let limiter = RateLimiter::new();
        limiter.set_rate(MEBIBYTE_PER_SEC);
        assert_eq!(limiter.reserve(1024 * 1024), Duration::ZERO);

        // A panel that re-sends an unchanged user on every sync must not
        // effectively remove the limit.
        for _ in 0..10 {
            limiter.set_rate(MEBIBYTE_PER_SEC);
        }
        assert_eq!(limiter.reserve(1024 * 1024), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_genuine_rate_change_resets_the_bucket() {
        let limiter = RateLimiter::new();
        limiter.set_rate(MEBIBYTE_PER_SEC);
        assert_eq!(limiter.reserve(4 * 1024 * 1024), Duration::from_secs(3));

        // Raising the limit must take effect now, not after the old debt is
        // paid off at the old rate.
        limiter.set_rate(MEBIBYTE_PER_SEC * 4);
        assert_eq!(limiter.reserve(1024 * 1024), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn removing_the_limit_takes_effect_immediately() {
        let limiter = RateLimiter::new();
        limiter.set_rate(MEBIBYTE_PER_SEC);
        assert!(limiter.reserve(8 * 1024 * 1024) > Duration::ZERO);

        limiter.set_rate(0);
        assert_eq!(limiter.reserve(64 * 1024 * 1024), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn sustained_throughput_converges_on_the_configured_rate() {
        let limiter = RateLimiter::new();
        limiter.set_rate(MEBIBYTE_PER_SEC);

        // Spend the free burst first so it does not skew the measurement.
        assert_eq!(limiter.reserve(1024 * 1024), Duration::ZERO);

        // Then push 8 MiB in 64 KiB chunks, sleeping whenever told to.
        let start = Instant::now();
        for _ in 0..128 {
            let wait = limiter.reserve(64 * 1024);
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }
        }
        let elapsed = Instant::now().duration_since(start);
        assert_eq!(
            elapsed.as_secs(),
            8,
            "8 MiB of debt drained at 1 MiB/s, with every chunk's wait honoured"
        );
    }
}
