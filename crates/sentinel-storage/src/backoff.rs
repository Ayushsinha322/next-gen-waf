//! Capped exponential backoff for the background storage connectors.
//!
//! Storage connects off the startup path and keeps retrying a backend that is
//! down, so the retry cadence has to be prompt at first (a Valkey/ClickHouse
//! that is merely still starting answers within seconds) and then settle at a
//! bounded rate (a backend that is gone for hours must not be hammered, nor
//! flood the log).

use std::time::{Duration, Instant};

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

/// Reconnect pacing for a writer whose connect can succeed while every write
/// fails: a ClickHouse that answers ping and DDL but rejects an insert (a bad
/// spool segment) or times it out (an overloaded server).
///
/// The delay is reset by a successful WRITE, or by a connection that stayed up
/// for [`SinkRetry::STABLE_AFTER`] before failing (the next outage is then a
/// new one, retried promptly). Resetting on connect, as the history writer
/// first did, retried such a sink at the initial delay for ever, re-running
/// the schema DDL and logging two warnings every couple of seconds.
#[derive(Debug, Clone)]
pub struct SinkRetry {
    backoff: Backoff,
    connected_at: Option<Instant>,
}

impl SinkRetry {
    /// A connection that lasted this long counts as having worked.
    pub const STABLE_AFTER: Duration = Duration::from_secs(60);

    pub fn new(initial: Duration, max: Duration) -> Self {
        Self {
            backoff: Backoff::new(initial, max),
            connected_at: None,
        }
    }

    /// The connect (ping + schema) succeeded. Deliberately not a reset.
    pub fn connected(&mut self, now: Instant) {
        self.connected_at = Some(now);
    }

    /// A write was accepted: the next outage is retried promptly.
    pub fn wrote(&mut self) {
        self.backoff.reset();
    }

    /// A connect or a write failed: how long to wait before reconnecting.
    pub fn failed(&mut self, now: Instant) -> Duration {
        if let Some(at) = self.connected_at.take() {
            if now.saturating_duration_since(at) >= Self::STABLE_AFTER {
                self.backoff.reset();
            }
        }
        self.backoff.next_delay()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The loop that never backed off: connect fine, fail the first write,
    /// reconnect, fail again — at the initial delay every time.
    #[test]
    fn a_sink_that_connects_but_never_takes_a_write_backs_off() {
        let t = Instant::now();
        let s = |n: u64| t + Duration::from_secs(n);
        let mut r = SinkRetry::new(Duration::from_secs(2), Duration::from_secs(60));
        let mut delays = Vec::new();
        let mut now = 0;
        for _ in 0..6 {
            r.connected(s(now));
            let d = r.failed(s(now + 1));
            delays.push(d.as_secs());
            now += 1 + d.as_secs();
        }
        assert_eq!(delays, vec![2, 4, 8, 16, 32, 60]);
    }

    #[test]
    fn a_write_or_a_long_lived_connection_resets_the_delay() {
        let t = Instant::now();
        let mut r = SinkRetry::new(Duration::from_secs(2), Duration::from_secs(60));
        r.failed(t);
        r.failed(t);
        r.wrote();
        assert_eq!(r.failed(t), Duration::from_secs(2), "after a good write");

        r.failed(t);
        r.connected(t);
        assert_eq!(
            r.failed(t + SinkRetry::STABLE_AFTER),
            Duration::from_secs(2),
            "after a connection that stayed up"
        );
    }

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
