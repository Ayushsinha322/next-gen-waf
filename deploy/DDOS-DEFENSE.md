# DDoS defence — layers, what is done, and what is honestly not

DDoS is not one problem, and this WAF cannot solve all of it. This document says
plainly which layers the product covers, which it now covers after Fix 10, and which are
a network/organisational decision that no amount of appliance code can substitute for.

Being clear about the last category matters commercially: HaltDOS-class volumetric
mitigation is a property of ESDS's network, not of a bigger box, and selling it as a box
feature is the kind of overstatement that a customer's first real attack exposes.

## The layers

| Layer | Attack | Where it must be handled | Status |
|---|---|---|---|
| Volumetric (L3/L4) | 100Gbps+ floods saturating the link | Upstream network: BGP Flowspec / RTBH / scrubbing | **Organisational — see below** |
| Protocol (L3/L4) | SYN / UDP / connection floods that fit the pipe | Host kernel + edge LB + XDP | **Addressed (Fix 10)** |
| Application (L7) | HTTP floods, slowloris, expensive endpoints | WAF rate limiter + HAProxy + timeouts | **Addressed** |
| Targeted (L7) | credential stuffing, scraping, per-endpoint abuse | WAF rules + bot detection + rate limits | Partial (bot feed still hardcoded — Fix 8) |

## What Fix 10 changed

### 1. The IP blocklist was inert behind a load balancer — fixed

The in-kernel/software blocklist fast-fail checked only the transport peer
(`peer.ip()`). Behind HAProxy — i.e. in the shipped HA topology, and behind any CDN or
ingress — every request's peer is the proxy, so the blocklist compared the proxy's
address and matched nothing. It appeared to work only in the single-VM demo, where the
client was the immediate peer.

It now also checks the resolved client IP (`resolve_client_ip`), which trusts
`X-Forwarded-For` only from a configured trusted proxy and walks the chain
right-to-left, so the header cannot be used to spoof past a block or to frame a third
party. Six regression tests in `crates/sentinel-proxy` cover both spoofing directions;
`blocklist_catches_client_behind_trusted_proxy` is the one that was failing before.

### 2. HAProxy stick-tables — new

`deploy/docker/haproxy.cfg` now sheds per-source floods at the edge, before a request is
proxied to the WAF: concurrent-connection cap, connection-rate cap, request-rate cap
(429), and error-rate cap. This is the cheapest place to reject a flood — the previous
config let every flood reach the WAF fleet, where rejecting it still cost a full parse
and a Redis round-trip.

The table keys on `src`, which is correct because HAProxy is the edge. **Do not copy
these rules to an inner proxy** — behind another LB `src` becomes that LB and all
counters collapse onto one key. That is the same class of bug as (1).

### 3. Host kernel + conntrack hardening — new

`deploy/hardening/99-sentinel-ddos.conf` + `harden-network.sh`: SYN cookies, deeper
backlogs, faster half-open reaping, reverse-path filtering, and — the one that matters
most under load — a conntrack table sized up AND a `NOTRACK` rule keeping the public WAF
ports out of connection tracking entirely. Conntrack's table is a lower ceiling than any
socket limit; when it fills the kernel drops new connections and logs
`nf_conntrack: table full`, which is usually misdiagnosed as an upstream fault. None of
these were set before.

### 4. A flood harness — new

`deploy/load-test/flood-test.sh` runs a SYN/UDP/connection flood while a stream of
legitimate requests runs alongside, and reports what the legitimate clients experienced.
The clean-traffic SLO — not "the flood was blocked" — is the pass/fail signal: a WAF that
survives a flood by also dropping real users has failed.

## XDP scope — what the in-kernel program can and cannot do

`crates/sentinel-ebpf` is a blocklist-only XDP program: it drops packets from addresses
in an LPM map and passes everything else. It does **not** do rate limiting, SYN-flag
filtering, or UDP-flood dropping in-kernel. Those were scoped for Fix 10 and are **not
implemented** — the protocol-flood defence above is currently the HAProxy + kernel
layer, not XDP.

Two honest constraints on the XDP path:

- **XDP runs at L3 and cannot see `X-Forwarded-For`.** So its blocklist is only
  meaningful where the packet source IS the client — i.e. at a true network edge, not on
  a node sitting behind another LB. Per-source XDP enforcement belongs on a dedicated
  edge tier; placing it on an inner node repeats the peer-vs-client bug at the packet
  level, where there is no XFF to recover the real source from.
- Auto-ban and connection-rate state are **per-node**. A flood spread across the fleet
  is not aggregated, so cross-node floods evade per-node thresholds. Making ban state
  cluster-wide via the existing Redis path is scoped and **not implemented**.

## Volumetric mitigation is ESDS's network, not this box — say so

No appliance mitigates a flood larger than its own uplink: the packets have already
consumed the link before any software sees them. Volumetric defence is a network-edge
function — BGP Flowspec to push filters upstream, RTBH to blackhole a target, or
diverting traffic through scrubbing capacity — and it lives on routers and transit ESDS
already operates.

That is the actual HaltDOS-class lever, and it is an advantage a pure-software competitor
does not have: ESDS owns the routers, transit, and peering. The work is a
**detection → BGP/scrubbing escalation hook** wired into that network edge (the WAF
detects and signals; the network diverts or filters), plus the operational capacity to
run it. It is an organisational and network-engineering decision, deliberately out of
scope for the appliance, and should be sold as a network service — not implied to be a
feature of the box.

## Verification status — read before quoting any of this

Everything in Fix 10 is **built and unit/config-validated, not yet flood-tested on real
hardware**:

- The blocklist fix has 6 passing regression tests.
- The HAProxy config validates under HAProxy 2.9 (`haproxy -c`).
- The sysctl/NOTRACK scripts are syntax-checked and idempotent, but have not been run
  against a live flood.
- `flood-test.sh` exists but **has not been run** — there is no measured "backend CPU
  stayed flat, p99 held" result yet.

So the correct claim today is "protocol-flood hardening is in place and needs a flood
drill to confirm", not "DDoS-hardened". The drill (`flood-test.sh`) plus the XDP and
cluster-wide-ban items above are what close the gap between the two statements.
