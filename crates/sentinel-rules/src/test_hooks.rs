//! Test-only control over the rule engine, compiled in for this crate's own
//! tests and, through the `test-hooks` feature, for other crates' tests. A
//! release build has none of it.

use std::cell::Cell;
use std::time::Duration;

thread_local! {
    static STEP: Cell<Duration> = const { Cell::new(Duration::ZERO) };
    static SKEW: Cell<Duration> = const { Cell::new(Duration::ZERO) };
}

/// Make the VM's clock on this thread run `step` further every time an
/// `evaluate` call reads it — once when the call starts, then every few dozen
/// instructions — so a time budget runs out on a fast request, at a known
/// read. `Duration::ZERO` puts the clock back. Per thread, so tests running
/// in parallel do not see each other's clocks.
pub fn set_eval_clock_step(step: Duration) {
    STEP.with(|s| s.set(step));
    SKEW.with(|s| s.set(Duration::ZERO));
}

/// How far the VM's clock is ahead of the real one: one more `step` per read.
pub(crate) fn eval_clock_skew() -> Duration {
    let step = STEP.with(Cell::get);
    SKEW.with(|s| {
        let skew = s.get() + step;
        s.set(skew);
        skew
    })
}
