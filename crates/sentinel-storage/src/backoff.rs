//! Capped exponential backoff for the background storage connectors.
//!
//! Storage connects off the startup path and keeps retrying a backend that is
//! down, so the retry cadence has to be prompt at first (a Valkey/ClickHouse
//! that is merely still starting answers within seconds) and then settle at a
//! bounded rate (a backend that is gone for hours must not be hammered, nor
//! flood the log).

use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Backoff {
    initial: Duration,
    max: Duration,
    next: Duration,
}

impl Backoff {
    /// Delays start at `initial` and double up to `max`.
    pub fn new(initial: Duration, max: Duration) -> Self {
        let initial = initial.min(max);
        Self {
            initial,
            max,
            next: initial,
        }
    }

    /// The delay to wait before the next attempt; advances the sequence.
    pub fn next_delay(&mut self) -> Duration {
        let d = self.next;
        self.next = self.next.saturating_mul(2).min(self.max);
        d
    }

    /// Back to the initial delay — call after a successful attempt so the
    /// next outage is again retried promptly.
    pub fn reset(&mut self) {
        self.next = self.initial;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doubles_up_to_the_cap_and_resets() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(5));
        let seq: Vec<u64> = (0..5).map(|_| b.next_delay().as_secs()).collect();
        assert_eq!(seq, vec![1, 2, 4, 5, 5]);
        b.reset();
        assert_eq!(b.next_delay(), Duration::from_secs(1));
    }

    #[test]
    fn initial_above_cap_is_clamped() {
        let mut b = Backoff::new(Duration::from_secs(10), Duration::from_secs(3));
        assert_eq!(b.next_delay(), Duration::from_secs(3));
        assert_eq!(b.next_delay(), Duration::from_secs(3));
    }
}
