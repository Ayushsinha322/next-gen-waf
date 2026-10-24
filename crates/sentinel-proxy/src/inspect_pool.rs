//! Where expensive inspection runs.
//!
//! Rule and ML inspection of a request or response body is CPU work: up to
//! about 2.6 s of one core for a body inside the default limits (measured
//! 2026-10-06: libinjection ~44 %, regex ~26 %). It ran inline on the async
//! workers, so a handful of concurrent large bodies held every worker and
//! delayed every other site's requests and the health probes with them — the
//! load balancer could take a healthy node out for answering /readyz late
//! (2026-10-07 review #28).
//!
//! A body of [`HEAVY_BYTES`] or more is now inspected with
//! `block_in_place`: the worker becomes a blocking thread for the duration and
//! the runtime hands its other tasks to a fresh worker, so the async side keeps
//! serving. At most [`pool_size`] such inspections run at once (one core is left
//! for everything else); the rest wait for a slot without holding a worker.
//! Small bodies stay inline: handing a worker off costs more than they do.
//!
//! The verdict is the same either way — only the thread it is computed on
//! differs.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::OnceLock;

use tokio::sync::Semaphore;

/// Bodies at or above this many bytes are inspected off the async workers.
pub(crate) const HEAVY_BYTES: usize = 32 * 1024;

static OFFLOADED: AtomicU64 = AtomicU64::new(0);
static WAITING: AtomicUsize = AtomicUsize::new(0);

/// How many heavy inspections may run at once: `SENTINEL_INSPECTION_THREADS`,
/// or one fewer than the cores this process may use (at least one).
pub(crate) fn pool_size() -> usize {
    std::env::var("SENTINEL_INSPECTION_THREADS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map_or(1, |n| n.get().saturating_sub(1))
                .max(1)
        })
}

fn permits() -> &'static Semaphore {
    static S: OnceLock<Semaphore> = OnceLock::new();
    S.get_or_init(|| Semaphore::new(pool_size()))
}

/// `block_in_place` exists only on the multi-threaded runtime (the proxy's);
/// a current-thread runtime (most tests) runs the work inline as before.
fn offload_possible() -> bool {
    tokio::runtime::Handle::try_current()
        .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
}

/// Run `inspect`, the CPU-bound inspection of a `len`-byte body, off the async
/// workers when it is heavy, within the pool's bound.
pub(crate) async fn run<R>(len: usize, inspect: impl FnOnce() -> R) -> R {
    if len < HEAVY_BYTES || !offload_possible() {
        return inspect();
    }
    WAITING.fetch_add(1, Ordering::Relaxed);
    let permit = permits().acquire().await;
    WAITING.fetch_sub(1, Ordering::Relaxed);
    let _permit = permit.expect("the inspection semaphore is never closed");
    OFFLOADED.fetch_add(1, Ordering::Relaxed);
    tokio::task::block_in_place(inspect)
}

/// The same for a synchronous caller — a WebSocket message is judged from a
/// callback. It waits for its slot off the worker: inside `block_in_place` the
/// thread is no worker any more, and may block on the semaphore.
///
/// This skipped the bound: heavy messages over many connections ran on as many
/// threads at once, every core included, which is what the pool exists to
/// prevent (external review 2026-10-22). The connection waiting for a slot
/// waits with it, which is the backpressure it should get.
pub(crate) fn run_now<R>(len: usize, inspect: impl FnOnce() -> R) -> R {
    if len < HEAVY_BYTES || !offload_possible() {
        return inspect();
    }
    tokio::task::block_in_place(|| {
        WAITING.fetch_add(1, Ordering::Relaxed);
        let permit = tokio::runtime::Handle::current().block_on(permits().acquire());
        WAITING.fetch_sub(1, Ordering::Relaxed);
        let _permit = permit.expect("the inspection semaphore is never closed");
        OFFLOADED.fetch_add(1, Ordering::Relaxed);
        inspect()
    })
}

/// For `/metrics`.
pub(crate) fn metrics_text() -> String {
    format!(
        "# HELP sentinel_inspection_offloaded_total Body inspections run off the async workers (bodies of {HEAVY_BYTES} bytes or more)\n\
         # TYPE sentinel_inspection_offloaded_total counter\n\
         sentinel_inspection_offloaded_total {}\n\
         # HELP sentinel_inspection_waiting Heavy inspections waiting for one of the {} slots\n\
         # TYPE sentinel_inspection_waiting gauge\n\
         sentinel_inspection_waiting {}\n",
        OFFLOADED.load(Ordering::Relaxed),
        pool_size(),
        WAITING.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// A heavy inspection holding a core for 600 ms on a runtime with one
    /// worker: inline, a task scheduled meanwhile waited the whole 600 ms (the
    /// worker was the inspection's); off the worker it runs on time.
    fn probe_delay_behind_inspection(len: usize) -> Duration {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let heavy = tokio::spawn(run(len, || std::thread::sleep(Duration::from_millis(600))));
            // Not a tokio timer: with the only worker held, nothing would drive
            // it, and the clock below would start only once the work was done.
            std::thread::sleep(Duration::from_millis(50));
            let t = Instant::now();
            assert_eq!(tokio::spawn(async { 1 + 1 }).await.unwrap(), 2);
            let waited = t.elapsed();
            heavy.await.unwrap();
            waited
        })
    }

    #[test]
    fn a_heavy_inspection_does_not_hold_up_other_tasks() {
        let waited = probe_delay_behind_inspection(HEAVY_BYTES);
        assert!(
            waited < Duration::from_millis(200),
            "a trivial task waited {waited:?} behind a heavy inspection"
        );
    }

    /// The control for the test above: the same work inline does hold the
    /// worker, so the test can tell the two apart.
    #[test]
    fn a_small_inspection_runs_inline_on_the_worker() {
        let waited = probe_delay_behind_inspection(HEAVY_BYTES - 1);
        assert!(
            waited >= Duration::from_millis(400),
            "inline work did not hold the worker ({waited:?}): the test above proves nothing"
        );
    }

    #[test]
    fn small_bodies_and_current_thread_runtimes_stay_inline() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        // block_in_place would panic here; run() must not call it.
        let v = rt.block_on(run(10 * HEAVY_BYTES, || 7));
        assert_eq!(v, 7);
        assert_eq!(run_now(10 * HEAVY_BYTES, || 8), 8);
    }

    /// Heavy inspections from synchronous callers run at most `pool_size` at
    /// once, as those from `run` do; and from `run` and `run_now` together.
    #[test]
    fn run_now_waits_for_a_slot_like_run() {
        use std::sync::Arc;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        let (now, max) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let work = {
            let (now, max) = (now.clone(), max.clone());
            move || {
                let n = now.fetch_add(1, Ordering::SeqCst) + 1;
                max.fetch_max(n, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(30));
                now.fetch_sub(1, Ordering::SeqCst);
            }
        };
        let jobs = 2 * pool_size() + 4;
        rt.block_on(async {
            let tasks: Vec<_> = (0..jobs)
                .map(|i| {
                    let work = work.clone();
                    tokio::spawn(async move {
                        if i % 2 == 0 {
                            run_now(HEAVY_BYTES, work);
                        } else {
                            run(HEAVY_BYTES, work).await;
                        }
                    })
                })
                .collect();
            for t in tasks {
                t.await.unwrap();
            }
        });
        let seen = max.load(Ordering::SeqCst);
        assert!(
            (1..=pool_size()).contains(&seen),
            "{seen} heavy inspections ran at once; the pool allows {}",
            pool_size()
        );
    }

    #[test]
    fn the_pool_leaves_a_core_and_reports_itself() {
        assert!(pool_size() >= 1);
        let m = metrics_text();
        assert!(m.contains("sentinel_inspection_offloaded_total "));
        assert!(m.contains("sentinel_inspection_waiting "));
    }
}
