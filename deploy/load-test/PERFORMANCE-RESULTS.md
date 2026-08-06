# Measured performance — Fix 3 verification

These are the drills that were outstanding after Fix 3 removed three per-request global
locks. Until they ran, "throughput now scales with cores" and "memory is constant" were
claims, not results. Both harnesses are committed (`scaling-sweep.sh`, `soak-test.sh`) so
anyone can reproduce or refute this.

## 1. CPU scaling — laptop (16-core AMD Ryzen 7 7730U)

Clean path: GET through the WAF to an nginx origin, full OWASP CRS 4.x, blocking mode,
PL2. WAF pinned to N cores; origin and generator pinned to a *different* set so the load
generator can never become the bottleneck.

| cores | rps | rps/core | p99 | success | efficiency vs 1 core |
|---|---|---|---|---|---|
| 1 | 956 | 956 | 87.6 ms | 100% | 1.00x |
| 2 | 1,365 | 682 | 67.0 ms | 100% | 0.71x |
| 4 | 2,910 | 728 | 35.2 ms | 100% | 0.76x |
| 8 | 5,939 | 742 | 18.1 ms | 100% | 0.78x |

**Result: the Fix 3 claim holds.** The signal is not absolute efficiency but that
efficiency STOPS FALLING: 71% -> 76% -> 78% from 2 to 8 cores, with per-core throughput
flat-to-rising (682 -> 728 -> 742). Lock contention produces the opposite signature —
efficiency degrading as cores increase, because more threads contend for the same cache
line. That is what the pre-fix code would have shown. There is no contention wall here.

The 1->2 step down is a one-time cost, not a trend: the single-core point pays no
cross-core cache traffic. Thread counts (3/4/6/10) confirm tokio sized its pool from the
CPU affinity mask, so this measured worker count rather than scheduler pressure.

## 2. CPU scaling — deploy VM (8 vCPU KVM, 172.16.21.71)

| cores | rps | rps/core | p99 | success | efficiency vs 1 core |
|---|---|---|---|---|---|
| 1 | 700 | 700 | 112.9 ms | 100% | 1.00x |
| 2 | 1,321 | 660 | 80.0 ms | 100% | 0.94x |
| 4 | 2,375 | 594 | 37.4 ms | 100% | 0.85x |

At 4 cores the VM reaches ~82% of the laptop's throughput — the expected cost of KVM
vCPUs versus physical cores. Measured to 4 cores only: 2 vCPUs were left to the live demo
stack and 2 to origin+generator.

**Projected 8-vCPU ceiling: roughly 4,000-4,500 rps** on the clean path. That is an
EXTRAPOLATION from a 1->4 curve with declining efficiency, not a measurement — do not
quote it as one.

### A note on method, because the first VM attempt was wrong

The first run reported 146% and 167% "efficiency" — physically impossible. Cause: the WAF
was pinned to core 0 while the demo stack's 14 containers were unpinned and free to use
it, crushing the 1-core baseline and inflating every ratio. Super-linear scaling is always
an artefact. The fix was to confine the demo to 2 cores with `docker update` (a live cgroup
change, no restart) rather than stopping a stack with weeks of uptime.

Caution if you repeat this: `docker update --cpuset-cpus=""` does NOT clear the pin on this
Docker version. Restoring requires setting the full range explicitly (`0-7`) and verifying
with `taskset -pc <pid>`.

## 3. Sustained soak — 30 minutes (laptop, 4 cores)

Bounded at 1,200 rps, ~40% of the measured 4-core ceiling. Deliberately below saturation:
a saturated run confounds the measurement, because queue growth and allocator behaviour
under backpressure both move RSS for reasons unrelated to a leak.

| | |
|---|---|
| Requests | **2,160,001** at a sustained 1,200.00 rps |
| Success | **100.00%** — all 200s, zero errors |
| Latency | mean 2.05 ms, p50 1.96 ms, p90 2.69 ms, p99 3.58 ms, max 52.3 ms |
| RSS, steady state | 70,160 -> 70,488 kB (**spread 328 kB over 25 min**) |
| RSS slope | **+0.74 MiB/hour** |
| Threads | 6 -> 6 (constant) |
| File descriptors | slope **-0.0093/s** (negative; churn, not a leak) |

**Result: memory is flat. The unbounded histogram leak is gone.** For scale on what this
rules out: the pre-fix code appended one `f64` per request to a `Vec` that was never
drained, so 2.16M requests would have accumulated **~17 MB minimum** in that buffer alone,
and `Vec` capacity doubling would have shown as visible step increases. Observed
steady-state growth was 0.33 MB.

### The verdict logic had a bug, now fixed

The first automated verdict said "memory is NOT flat" at +7.99 MiB/hour. That was a false
positive from regressing over ALL samples including warmup: RSS climbs 42 MB -> 68 MB in
the first 60 seconds as connection pools, rule caches and allocator arenas populate, and
that single step was ~28 MB of a ~28 MB total spread. The slope was measuring startup, not
leakage. `soak-test.sh` now excludes a `WARMUP_S` window (default 300s) before regressing,
and reports steady-state growth rather than start-vs-end.

Worth remembering generally: on any soak, a warmup ramp will masquerade as a leak in a
whole-run regression, and endpoint-to-endpoint fd comparisons will masquerade as fd leaks.
Judge the trend after the working set settles.

## What these drills do NOT establish

- **Scaling beyond 8 cores is unmeasured.** The generator needed the other cores. The
  claim "scales to 32 cores" remains unverified.
- **The VM's 8-vCPU ceiling is projected, not measured** (see above).
- **6% steal time** was observed on the VM in one sample (0% in others). On a shared
  hypervisor the ceiling is partly the host's, not the guest's. Check `vmstat` while
  running.
- **A longer soak would be stronger.** 30 minutes at 1,200 rps is 2.16M requests; a
  24-hour run at production rate would catch slower leaks this cannot see.
- **This is the clean path only.** The block path is faster (early exit, no upstream
  fetch) and is not what these numbers describe.
