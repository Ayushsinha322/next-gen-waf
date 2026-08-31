# On-box verification

Scripts that check a **running** WAF by sending real traffic and reading the
resulting logs. They exist because the unit suite cannot answer the question
these do: whether the deployed binary, with the site's real policy, actually
behaves as intended.

Run them ON the WAF host, after a deploy:

    ./verify-redaction.sh                 # credentials in / evidence out
    ./verify-log-privacy-and-rules.sh     # framework cookies, CRS coverage, ACME

Both exit non-zero on failure, so they can gate a rollout.

## Why each one checks BOTH directions

Every check has a matching opposite. A redaction pass that removes credentials
is only half-right; if it also removes the attack payload, the log stops being
worth keeping. Six defects in the redaction work were found this way and **two of
them were over-redaction** — the cookie jar swallowing payloads, and `?author=`
hiding WordPress user enumeration behind `[redacted]`. Neither was visible in a
unit test; both were obvious in one line of real log output.

So: eight credentials that must vanish, and `?author=` plus an ordinary cookie's
SQLi payload that must survive.

## Two traps these scripts hit, now avoided

1. **Grepping the whole log file.** Pre-deploy lines are still in it. A `sid=`
   in the clear from before the fix reads as the fix having failed. Every check
   that inspects log content is scoped to the current containers' start time.

2. **Probing a rule that a sibling rule masks.** Sending an AngularJS template
   payload to `/` never showed rule 941380, because 941390 fires first, the
   anomaly score passes the threshold, and evaluation short-circuits. The rule
   was working; the probe was wrong. Send each payload somewhere the rest of its
   family stays quiet.

Both produced a confident, wrong result before being fixed — which is the same
failure the tools in `../load-test/` exist to prevent for the FPR pilot.

## Answering the false-positive question honestly

`fp-recheck.sh` is READ-ONLY on purpose. The battery in
`verify-protocol-rules.sh` sends probes, so re-running it hourly to answer "did
the new rules false-positive?" would pollute the very sample the answer depends
on — and that sample is a live FPR pilot window.

It exits **2 = INCONCLUSIVE** below 100 real human requests rather than 0. This
is the point: "nothing fired" over an empty sample is not evidence, it is a
guard that cannot fail. That mistake has been made in this repo before — a
report once read "0.1824%, under the gate" when 364 of 373 requests were
keepalived's own health check.

`fp-watch.sh` polls it and records a verdict once, when the sample is finally
big enough. Detached, so a VPN drop cannot interrupt it, and it writes
`TIMED OUT ... Not a pass` rather than a pass if nobody browses enough.

### Two shell traps hit while writing these

`pkill -f fp-watch.sh` run over SSH kills the SSH session itself, because the
remote command line contains that string. Same for `pgrep -cf` — it counts
itself and reports 1 for a process that is not running. Match on
`/proc/<pid>/cmdline` and exclude `$$` instead. Both produced a confidently
wrong answer here: "watcher running: 1" when it had never started.
