use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug)]
struct TimeEntry {
    instant: Instant,
    value: Arc<[u8]>,
}

/// Remembers the values seen in the last `window`, so a recorded handshake cannot
/// be replayed inside it.
///
/// Two protocols need this and they need the same thing: Shadowsocks against a
/// replayed AEAD salt, VMess against a replayed auth id. Both are a short opaque
/// byte string that must be rejected the second time it is seen and forgotten once
/// it can no longer be fresh, so they share one implementation rather than growing
/// two that drift.
///
/// # Exact, not probabilistic
///
/// A Bloom or cuckoo filter would be smaller, and it is what several older
/// Shadowsocks implementations reached for. SIP022 forbids it, and the reason
/// generalises to VMess: a false positive here is not a tolerable approximation,
/// it is a legitimate user refused for a handshake nobody replayed, and the odds of
/// it rise as the filter fills. Values only have to be held for a minute or two, so
/// an exact set is affordable and is what this keeps.
///
/// # One value, one allocation
///
/// The two structures hold the same values for the same span of time: the set answers
/// "have I seen this", and the queue answers "which is the oldest". They share an
/// `Arc<[u8]>` rather than each owning a copy. That is worth doing because what sizes
/// this filter is not under our control -- Shadowsocks records a salt before the
/// record layer has opened anything, so anyone who can complete a TCP handshake can
/// put one in here for the whole window. Halving the resident cost is free; the
/// `HashSet` still hashes and compares the bytes, since `Arc<[u8]>` borrows as `[u8]`.
///
/// # Sizing
///
/// There is no entry ceiling, only the window. That matches both reference
/// implementations -- sing-box's `replay.SimpleFilter` and Xray's `antireplay`
/// filter are each bounded by time alone -- and a ceiling would be worse than it
/// looks: refusing new values once full hands an attacker a way to lock legitimate
/// clients out, and evicting early silently shortens the replay window that is the
/// whole point. Feed it only values that have already passed a cheap authenticity
/// check, and the window is the bound.
#[derive(Debug)]
pub struct ReplayFilter {
    by_age: VecDeque<TimeEntry>,
    seen: HashSet<Arc<[u8]>>,
    window: Duration,
}

impl ReplayFilter {
    pub fn new(window: Duration) -> Self {
        Self {
            by_age: VecDeque::with_capacity(2000),
            seen: HashSet::with_capacity(2000),
            window,
        }
    }

    /// Record `value` and report whether it is new. `false` means a replay.
    pub fn check_and_insert(&mut self, value: &[u8]) -> bool {
        while let Some(time_entry) = self.by_age.front() {
            if time_entry.instant.elapsed() < self.window {
                break;
            }
            self.seen.remove(&time_entry.value);
            self.by_age.pop_front();
        }

        if self.seen.contains(value) {
            return false;
        }

        let value: Arc<[u8]> = Arc::from(value);
        self.seen.insert(Arc::clone(&value));
        self.by_age.push_back(TimeEntry {
            instant: Instant::now(),
            value,
        });

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_is_accepted_once_and_refused_after() {
        let mut checker = ReplayFilter::new(Duration::from_secs(60));
        assert!(checker.check_and_insert(b"the-first-salt"));
        assert!(
            !checker.check_and_insert(b"the-first-salt"),
            "the replay is what this exists to catch"
        );
        assert!(checker.check_and_insert(b"a-different-salt"));
    }

    #[test]
    fn expired_values_leave_both_structures() {
        // A zero second window expires everything on the next call, which is the
        // cheapest way to prove the sweep clears the set and not only the queue --
        // a leak there would grow without bound and never be visible from outside.
        let mut checker = ReplayFilter::new(Duration::ZERO);
        assert!(checker.check_and_insert(b"salt"));
        assert!(
            checker.check_and_insert(b"salt"),
            "the window has passed, so this is a new salt again"
        );
        assert_eq!(checker.seen.len(), 1);
        assert_eq!(checker.by_age.len(), 1);
    }

    #[test]
    fn the_set_and_the_queue_share_one_allocation_per_value() {
        let mut checker = ReplayFilter::new(Duration::from_secs(60));
        assert!(checker.check_and_insert(b"salt"));

        let queued = &checker.by_age.front().expect("one entry").value;
        let held = checker.seen.get(&b"salt"[..]).expect("in the set");
        assert!(
            Arc::ptr_eq(queued, held),
            "both structures must point at the same bytes"
        );
        assert_eq!(Arc::strong_count(queued), 2);
    }
}
