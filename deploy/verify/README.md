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
