//! Test-only control over the rule engine, compiled in for this crate's own
//! tests and, through the `test-hooks` feature, for other crates' tests. A
//! release build has none of it.

use std::cell::Cell;
use std::time::Duration;

/// One of the VM's clocks on this thread: how far it moves per read, and how
/// far ahead of the real one it is so far.
struct Skewed {
    step: Cell<Duration>,
    skew: Cell<Duration>,
}

impl Skewed {
    const fn new() -> Self {
        Self {
            step: Cell::new(Duration::ZERO),
            skew: Cell::new(Duration::ZERO),
        }
    }

    fn set(&self, step: Duration) {
        self.step.set(step);
        self.skew.set(Duration::ZERO);
    }

    /// One more `step` per read.
    fn read(&self) -> Duration {
        let skew = self.skew.get() + self.step.get();
        self.skew.set(skew);
        skew
    }
}

thread_local! {
    static WALL: Skewed = const { Skewed::new() };
    static CPU: Skewed = const { Skewed::new() };
}

/// Make the VM's clocks on this thread run `step` further every time an
/// `evaluate` call reads them — when the call starts, then every few dozen
/// instructions — as if evaluating took that long: the wall clock and the
/// thread's CPU clock alike. A time budget then runs out on a fast request,
/// at a known read. `Duration::ZERO` puts both clocks back. Per thread, so
/// tests running in parallel do not see each other's clocks.
pub fn set_eval_clock_step(step: Duration) {
    WALL.with(|c| c.set(step));
    CPU.with(|c| c.set(step));
}

/// Move the wall clock alone `step` per read, as if the thread were
/// descheduled between reads and used no CPU: a busy node, not a slow
/// request. Reset with `set_eval_clock_step(Duration::ZERO)`.
pub fn set_eval_wall_clock_step(step: Duration) {
    WALL.with(|c| c.set(step));
    CPU.with(|c| c.set(Duration::ZERO));
}

/// How far the VM's wall clock is ahead of the real one: one more step per
/// read.
pub(crate) fn eval_clock_skew() -> Duration {
    WALL.with(Skewed::read)
}

/// How far the VM's CPU clock is ahead of the thread's real CPU time.
pub(crate) fn eval_cpu_clock_skew() -> Duration {
    CPU.with(Skewed::read)
}
