#!/usr/bin/env python3
"""Sentinel WAF — CXO / client pitch deck generator (12 slides)."""

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE
from pptx.oxml.ns import qn

# ---------------------------------------------------------------- palette
BG       = RGBColor(0x0B, 0x12, 0x20)   # deep navy
PANEL    = RGBColor(0x13, 0x1E, 0x33)   # panel navy
PANEL2   = RGBColor(0x1B, 0x2A, 0x45)   # lighter panel
CYAN     = RGBColor(0x35, 0xE0, 0xC8)   # sentinel cyan/teal
GREEN    = RGBColor(0x3D, 0xDC, 0x84)   # success green
BLUE     = RGBColor(0x4E, 0x9C, 0xF5)   # accent blue
RED      = RGBColor(0xF2, 0x55, 0x5A)   # danger red
ORANGE   = RGBColor(0xF5, 0xA6, 0x23)   # warn orange
WHITE    = RGBColor(0xF4, 0xF7, 0xFB)
GREY     = RGBColor(0x9F, 0xB0, 0xC8)
DGREY    = RGBColor(0x6B, 0x7C, 0x96)

prs = Presentation()
prs.slide_width  = Inches(13.333)
prs.slide_height = Inches(7.5)
SW, SH = prs.slide_width, prs.slide_height
BLANK = prs.slide_layouts[6]


# ---------------------------------------------------------------- helpers
def slide():
    s = prs.slides.add_slide(BLANK)
    r = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SW, SH)
    r.fill.solid(); r.fill.fore_color.rgb = BG
    r.line.fill.background()
    r.shadow.inherit = False
    return s


def _set_font(run, size, color, bold=False, italic=False, name="Calibri"):
    run.font.size = Pt(size)
    run.font.color.rgb = color
    run.font.bold = bold
    run.font.italic = italic
    run.font.name = name


def text(s, l, t, w, h, lines, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP):
    """lines = list of (txt, size, color, bold, italic) or dicts."""
    tb = s.shapes.add_textbox(l, t, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    tf.margin_left = Pt(4); tf.margin_right = Pt(4)
    tf.margin_top = Pt(2); tf.margin_bottom = Pt(2)
    for i, ln in enumerate(lines):
        txt, size, color = ln[0], ln[1], ln[2]
        bold = ln[3] if len(ln) > 3 else False
        italic = ln[4] if len(ln) > 4 else False
        space = ln[5] if len(ln) > 5 else 4
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        p.space_after = Pt(space)
        p.line_spacing = 1.05
        r = p.add_run(); r.text = txt
        _set_font(r, size, color, bold, italic)
    return tb


def box(s, l, t, w, h, fill=PANEL, line=None, lw=1.0, rounded=True, shadow=False):
    shp = s.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE if rounded else MSO_SHAPE.RECTANGLE, l, t, w, h)
    shp.fill.solid(); shp.fill.fore_color.rgb = fill
    if line is None:
        shp.line.fill.background()
    else:
        shp.line.color.rgb = line; shp.line.width = Pt(lw)
    shp.shadow.inherit = False
    if rounded:
        try:
            shp.adjustments[0] = 0.06
        except Exception:
            pass
    return shp


def accent_bar(s, color=CYAN):
    box(s, 0, 0, Inches(0.16), SH, fill=color, rounded=False)


def header(s, kicker, title, color=CYAN):
    accent_bar(s, color)
    text(s, Inches(0.55), Inches(0.35), Inches(12), Inches(0.4),
         [(kicker.upper(), 13, color, True)])
    text(s, Inches(0.52), Inches(0.62), Inches(12.4), Inches(0.9),
         [(title, 30, WHITE, True)])
    ln = box(s, Inches(0.58), Inches(1.42), Inches(2.2), Pt(3), fill=color, rounded=False)
    return ln


def chip(s, l, t, w, h, label, val, vcolor, lcolor=GREY, fill=PANEL):
    box(s, l, t, w, h, fill=fill)
    text(s, l, t + Inches(0.12), w, Inches(0.5),
         [(val, 25, vcolor, True)], align=PP_ALIGN.CENTER)
    text(s, l, t + h - Inches(0.42), w, Inches(0.35),
         [(label, 10.5, lcolor, False)], align=PP_ALIGN.CENTER)


def arrow_down(s, cx, t, h=Inches(0.32), color=CYAN):
    a = s.shapes.add_shape(MSO_SHAPE.DOWN_ARROW, cx - Inches(0.13), t, Inches(0.26), h)
    a.fill.solid(); a.fill.fore_color.rgb = color
    a.line.fill.background(); a.shadow.inherit = False


def arrow_right(s, l, cy, w=Inches(0.34), color=CYAN):
    a = s.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW, l, cy - Inches(0.11), w, Inches(0.22))
    a.fill.solid(); a.fill.fore_color.rgb = color
    a.line.fill.background(); a.shadow.inherit = False


TOTAL = 13

def footer(s, n):
    text(s, Inches(0.55), Inches(7.08), Inches(8), Inches(0.3),
         [("SENTINEL WAF  ·  ESDS Networks Pvt. Ltd.", 9, DGREY)])
    text(s, Inches(11.6), Inches(7.08), Inches(1.5), Inches(0.3),
         [(f"{n} / {TOTAL}", 9, DGREY)], align=PP_ALIGN.RIGHT)


# ================================================================ SLIDE 1
s = slide()
box(s, 0, 0, Inches(0.16), SH, fill=CYAN, rounded=False)
box(s, 0, SH - Inches(0.16), SW, Inches(0.16), fill=CYAN, rounded=False)
# shield mark
sh = s.shapes.add_shape(MSO_SHAPE.PENTAGON, Inches(0.9), Inches(2.45), Inches(1.5), Inches(1.6))
sh.rotation = 90
sh.fill.solid(); sh.fill.fore_color.rgb = PANEL2
sh.line.color.rgb = CYAN; sh.line.width = Pt(2.5); sh.shadow.inherit = False
text(s, Inches(0.9), Inches(2.95), Inches(1.5), Inches(0.7), [("🛡", 40, CYAN, True)],
     align=PP_ALIGN.CENTER)
text(s, Inches(2.7), Inches(2.05), Inches(10), Inches(1.0),
     [("SENTINEL WAF", 54, WHITE, True)])
text(s, Inches(2.75), Inches(3.05), Inches(10), Inches(0.6),
     [("The Web Application Firewall, rebuilt for 2026", 22, CYAN, False, True)])
text(s, Inches(2.75), Inches(3.75), Inches(9.8), Inches(1.3),
     [("A next-generation WAF — Rust data plane + Go control plane.", 16, GREY),
      ("Sub-millisecond protection. AI-native detection. Kernel-level DDoS defence.", 16, GREY),
      ("Built to out-perform ModSecurity, Coraza, BunkerWeb and commercial cloud WAFs.", 16, GREY)])
# tag chips
tags = ["RUST DATA PLANE", "eBPF / XDP", "AI / ML BUILT-IN", "WASM PLUGINS", "RAFT HA"]
x = Inches(2.75)
for tg in tags:
    w = Inches(0.18 + 0.105 * len(tg))
    box(s, x, Inches(5.35), w, Inches(0.45), fill=PANEL, line=CYAN, lw=1)
    text(s, x, Inches(5.43), w, Inches(0.3), [(tg, 10.5, CYAN, True)], align=PP_ALIGN.CENTER)
    x += w + Inches(0.18)
text(s, Inches(2.75), Inches(6.35), Inches(10), Inches(0.4),
     [("Engineering Overview & Competitive Positioning  ·  ESDS Networks Pvt. Ltd.", 13, DGREY, True)])


# ================================================================ SLIDE 2 — Problem
s = slide()
header(s, "The Problem", "Why legacy WAFs fail in 2026", RED)
probs = [
    ("🐌", "Slow by design — O(n) / O(n\u00b2)", RED,
     "ModSecurity scores every request against ALL rules (1…9000), even after an attack "
     "is already detected. A messy payload spikes CPU and triggers ReDoS — the WAF itself "
     "becomes the DoS target."),
    ("💥", "DDoS reaches the application", ORANGE,
     "Traditional WAFs only see traffic AFTER the kernel builds TCP state, allocates memory "
     "and copies packets. At 10M SYN/s the server's CPU, RAM and kernel are exhausted before "
     "the WAF can act. The server dies before the WAF helps."),
    ("🧠", "No intelligence", ORANGE,
     "Pure regex/signature engines miss obfuscated payloads and zero-days. No ML, no anomaly "
     "scoring, no learning — they only catch what someone already wrote a rule for."),
    ("🔒", "Memory-unsafe & locked-in", RED,
     "ModSecurity (C) has 30+ memory-safety CVEs — a buffer overflow can hand the firewall to "
     "the attacker. Cloud WAFs lock you in, charge per request, and route your data off-network."),
]
yy = Inches(1.75)
for icon, t, c, d in probs:
    box(s, Inches(0.55), yy, Inches(12.25), Inches(1.16), fill=PANEL)
    box(s, Inches(0.55), yy, Inches(0.12), Inches(1.16), fill=c, rounded=False)
    text(s, Inches(0.8), yy + Inches(0.18), Inches(0.9), Inches(0.8), [(icon, 30, c)],
         align=PP_ALIGN.CENTER)
    text(s, Inches(1.75), yy + Inches(0.12), Inches(10.8), Inches(0.4),
         [(t, 17, WHITE, True)])
    text(s, Inches(1.75), yy + Inches(0.5), Inches(10.85), Inches(0.6),
         [(d, 12.5, GREY)])
    yy += Inches(1.27)
footer(s, 2)


# ================================================================ SLIDE 3 — What is Sentinel
s = slide()
header(s, "The Solution", "What Sentinel actually is", CYAN)
text(s, Inches(0.55), Inches(1.65), Inches(12.3), Inches(0.8),
     [("One self-contained binary that fuses a high-performance reverse proxy, a compiled "
       "rule engine, ML inference and kernel-level DDoS defence — managed by a clustered "
       "Go control plane and a modern dashboard.", 15, GREY)])
cards = [
    ("⚡ Rust Data Plane", CYAN,
     ["Zero garbage collector, memory-safe",
      "Proxy + WAF fused in ONE process",
      "Custom bytecode rule-engine VM",
      "p99 latency under 1 ms"]),
    ("🧩 Go Control Plane", BLUE,
     ["Raft active/active HA cluster",
      "REST + gRPC admin APIs",
      "RBAC, audit, multi-tenant",
      "Config push to all nodes < 200 ms"]),
    ("🤖 Intelligence Layer", GREEN,
     ["ONNX anomaly + payload ML models",
      "LLM rule copilot",
      "Egress DLP (PII / secrets)",
      "WASM plugins in any language"]),
]
cw = Inches(3.95); gap = Inches(0.22); x = Inches(0.55)
for title, c, items in cards:
    box(s, x, Inches(2.6), cw, Inches(3.05), fill=PANEL, line=c, lw=1.2)
    box(s, x, Inches(2.6), cw, Inches(0.62), fill=PANEL2)
    text(s, x, Inches(2.72), cw, Inches(0.45), [(title, 16, c, True)], align=PP_ALIGN.CENTER)
    text(s, x + Inches(0.28), Inches(3.45), cw - Inches(0.5), Inches(2.0),
         [("●  " + it, 13, WHITE, False, False, 9) for it in items])
    x += cw + gap
# stat strip
chips = [("300+", "Rust tests passing", GREEN), ("0", "test failures", GREEN),
         ("40 µs", "rule scan / request", CYAN), ("505 ns", "block an attacker", CYAN)]
x = Inches(0.55)
for v, l, c in chips:
    chip(s, x, Inches(5.95), Inches(3.0), Inches(0.95), l, v, c)
    x += Inches(3.05)
footer(s, 3)


# ================================================================ SLIDE 4 — Architecture
s = slide()
header(s, "Architecture", "End-to-end request flow", CYAN)

def layer(cx_l, t, w, h, title, sub, fill, line, tcolor):
    box(s, cx_l, t, w, h, fill=fill, line=line, lw=1.3)
    text(s, cx_l, t + Inches(0.1), w, Inches(0.4), [(title, 15, tcolor, True)],
         align=PP_ALIGN.CENTER)
    if sub:
        text(s, cx_l, t + Inches(0.46), w, h - Inches(0.5), [(sub, 11, GREY)],
             align=PP_ALIGN.CENTER)

midL = Inches(3.4); midW = Inches(6.5)
cx = midL + midW / 2
layer(midL, Inches(1.62), midW, Inches(0.6), "🌐 Internet / Clients", "", PANEL2, BLUE, WHITE)
arrow_down(s, cx, Inches(2.26), color=RED)
layer(midL, Inches(2.62), midW, Inches(0.66), "🛡 eBPF / XDP — L4 filter (Linux kernel)",
      "SYN-flood & known-bad IPs dropped at the NIC, before TCP", PANEL2, RED, RED)
arrow_down(s, cx, Inches(3.34), color=CYAN)

# data plane big box
dpL = Inches(1.4); dpW = Inches(10.55)
box(s, dpL, Inches(3.7), dpW, Inches(1.7), fill=PANEL, line=CYAN, lw=1.6)
text(s, dpL, Inches(3.78), dpW, Inches(0.35),
     [("SENTINEL DATA PLANE  (Rust — proxy + WAF fused)", 13.5, CYAN, True)],
     align=PP_ALIGN.CENTER)
stages = ["TLS / QUIC", "HTTP Parse", "Rule Engine", "ML Infer", "Upstream"]
sw = Inches(1.85); sx = dpL + Inches(0.35)
for i, st in enumerate(stages):
    box(s, sx, Inches(4.2), sw, Inches(0.52), fill=PANEL2, line=CYAN, lw=1)
    text(s, sx, Inches(4.3), sw, Inches(0.34), [(st, 12.5, WHITE, True)], align=PP_ALIGN.CENTER)
    if i < len(stages) - 1:
        arrow_right(s, sx + sw - Inches(0.02), Inches(4.46), Inches(0.22), CYAN)
    sx += sw + Inches(0.20)
text(s, dpL, Inches(4.92), dpW, Inches(0.42),
     [("WASM plugins · IP reputation · GeoIP · Rate-limit · Bot detect · DLP · JA4 fingerprint",
       11, GREY)], align=PP_ALIGN.CENTER)
arrow_down(s, cx, Inches(5.46), color=BLUE)
text(s, cx + Inches(0.2), Inches(5.5), Inches(1.4), Inches(0.3), [("gRPC", 10, BLUE, True)])

layer(midL, Inches(5.82), midW, Inches(0.66), "🧩 Control Plane (Go) — Raft cluster",
      "Admin API · RBAC · Audit · Config · Multi-tenant", PANEL2, BLUE, BLUE)
arrow_down(s, cx, Inches(6.54), color=GREEN)
layer(Inches(4.6), Inches(6.9), Inches(4.1), Inches(0.48),
      "🖥 Dashboard (Next.js + TypeScript)", "", PANEL2, GREEN, GREEN)
footer(s, 4)


# ================================================================ SLIDE 5 — eBPF deep dive
s = slide()
header(s, "Deep Dive · DDoS", "eBPF/XDP — kill packets in the kernel", RED)
text(s, Inches(0.55), Inches(1.6), Inches(12.2), Inches(0.55),
     [("A normal WAF only sees a packet after the kernel has already spent CPU, RAM, "
       "interrupts and TCP state on it. Sentinel drops bad packets at the NIC — before any "
       "of that cost is paid.", 13.5, GREY)])

def pipeline(title, t, steps, color, last_label):
    text(s, title[1], t, Inches(5.6), Inches(0.4), [(title[0], 16, color, True)])
    yy = t + Inches(0.5)
    bx = title[1]
    for i, st in enumerate(steps):
        is_last = i == len(steps) - 1
        f = color if is_last else PANEL
        box(s, bx, yy, Inches(4.7), Inches(0.42), fill=f, line=color if not is_last else None, lw=1)
        text(s, bx, yy + Inches(0.06), Inches(4.7), Inches(0.32),
             [(st, 12.5, BG if is_last else WHITE, is_last)], align=PP_ALIGN.CENTER)
        if not is_last:
            arrow_down(s, bx + Inches(2.35), yy + Inches(0.42), Inches(0.2), color)
        yy += Inches(0.62)
    text(s, bx, yy + Inches(0.04), Inches(4.7), Inches(0.4),
         [(last_label, 12, color, True)], align=PP_ALIGN.CENTER)

pipeline(("❌ TRADITIONAL WAF", Inches(0.7)), Inches(2.35),
         ["NIC", "Kernel TCP / IP stack", "Socket + memory allocated",
          "Nginx / proxy", "WAF engine → DROP"],
         RED, "CPU + RAM + kernel exhausted → server dies")
pipeline(("✅ SENTINEL with eBPF/XDP", Inches(7.0)), Inches(2.35),
         ["NIC", "eBPF / XDP hook (in kernel)", "DROP immediately"],
         GREEN, "0 CPU spent · packet dies instantly · line-rate")

box(s, Inches(0.7), Inches(6.35), Inches(11.9), Inches(0.7), fill=PANEL, line=RED, lw=1)
text(s, Inches(0.95), Inches(6.46), Inches(11.5), Inches(0.5),
     [("Example: 10,000,000 SYN/s flood — a userspace WAF chokes even while \"blocking\". "
       "Sentinel's XDP hook drops 99.9% before the WAF process sees a single packet.",
       13, WHITE)], anchor=MSO_ANCHOR.MIDDLE)
footer(s, 5)


# ================================================================ SLIDE 6 — O(1) engine
s = slide()
header(s, "Deep Dive · Engine", "O(1) early-exit vs O(n) legacy scoring", CYAN)

box(s, Inches(0.55), Inches(1.65), Inches(6.0), Inches(2.55), fill=PANEL, line=RED, lw=1.2)
text(s, Inches(0.8), Inches(1.78), Inches(5.5), Inches(0.4), [("ModSecurity — O(n) linear", 16, RED, True)])
text(s, Inches(0.8), Inches(2.25), Inches(5.5), Inches(1.9),
     [("Scores a request against EVERY rule. Even after rule 3 detects an obvious SQL injection, "
       "it keeps evaluating rules 4 … 9000.", 12.5, GREY, False, False, 8),
      ("Time grows linearly with rule count. A crafted messy payload forces heavy regex math on "
       "every rule → CPU spike → ReDoS.", 12.5, GREY, False, False, 8),
      ("➜ ~1,000,000 ns to block an attacker", 13.5, RED, True)])

box(s, Inches(6.78), Inches(1.65), Inches(6.0), Inches(2.55), fill=PANEL, line=GREEN, lw=1.2)
text(s, Inches(7.03), Inches(1.78), Inches(5.5), Inches(0.4),
     [("Sentinel — O(1) early-exit", 16, GREEN, True)])
text(s, Inches(7.03), Inches(2.25), Inches(5.5), Inches(1.9),
     [("Aho-Corasick matches all 200 patterns in ONE pass; the bytecode VM dispatches only the "
       "rules that actually fired.", 12.5, GREY, False, False, 8),
      ("The instant the anomaly score crosses threshold the VM halts — blocks, drops the "
       "connection, frees memory. Rules 4…900 are never read.", 12.5, GREY, False, False, 8),
      ("➜ 505 ns to block — same time at 10 or 10,000 rules", 13.5, GREEN, True)])

# code snippet
box(s, Inches(0.55), Inches(4.35), Inches(6.0), Inches(1.35), fill=RGBColor(0x07,0x0C,0x16))
text(s, Inches(0.8), Inches(4.5), Inches(5.6), Inches(1.1),
     [("if anomaly_score >= 5 {", 13, CYAN, False, False, 2),
      ("    block_request();", 13, GREEN, False, False, 2),
      ("    stop_execution();   // never reads rule 4…900", 13, GREY, False, False, 2),
      ("}", 13, CYAN)], )
# metrics
chip(s, Inches(6.78), Inches(4.35), Inches(1.9), Inches(1.35), "rule scan (200)", "40 µs", CYAN)
chip(s, Inches(8.83), Inches(4.35), Inches(1.9), Inches(1.35), "block attacker", "505 ns", GREEN)
chip(s, Inches(10.88), Inches(4.35), Inches(1.92), Inches(1.35), "vs full scan", "71×", ORANGE)

box(s, Inches(0.55), Inches(5.9), Inches(12.27), Inches(0.95), fill=PANEL2)
text(s, Inches(0.8), Inches(6.02), Inches(11.9), Inches(0.75),
     [("Proven linear scaling — 50 rules: 10 µs · 100: 22 µs · 200: 40 µs · 500: 106 µs. "
       "No quadratic cliff, no GC jitter. p99 ≈ p50, std-dev < 1 µs. Load the full OWASP CRS "
       "plus custom rules with zero fear of collapse.", 13, WHITE)],
     anchor=MSO_ANCHOR.MIDDLE)
footer(s, 6)


# ================================================================ SLIDE 7 — Why Rust
s = slide()
header(s, "Foundation", "Why Rust — safety AND speed", ORANGE)
text(s, Inches(0.55), Inches(1.62), Inches(12.2), Inches(0.7),
     [("A WAF parses the most hostile, malformed data on the internet. In C/C++ one mistake = "
       "a buffer overflow that hands the firewall to the attacker. Rust guarantees memory safety "
       "at compile time — so the VM can rip apart toxic payloads at line speed with zero risk of "
       "a segfault or memory leak.", 14, GREY)])
items = [
    ("No garbage collector", GREEN,
     "Flat p99 latency. Coraza (Go) suffers 0.1–10 ms stop-the-world pauses; Sentinel has none."),
    ("Compile-time memory safety", GREEN,
     "No buffer overflows, no use-after-free. ModSecurity (C) has 30+ memory-safety CVEs; "
     "Sentinel architecturally cannot have them."),
    ("Zero-cost abstractions", CYAN,
     "High-level iterators & pattern matching compile to the same assembly as hand-tuned C — "
     "no penalty for clean code."),
    ("Inlined hot paths", CYAN,
     "The rule-matching inner loop is fully inlined — no function-call overhead in the critical path."),
]
yy = Inches(2.7)
for t, c, d in items:
    box(s, Inches(0.55), yy, Inches(12.27), Inches(0.92), fill=PANEL)
    box(s, Inches(0.55), yy, Inches(0.12), Inches(0.92), fill=c, rounded=False)
    text(s, Inches(0.95), yy + Inches(0.13), Inches(4.0), Inches(0.7),
         [(t, 15.5, c, True)], anchor=MSO_ANCHOR.MIDDLE)
    text(s, Inches(5.0), yy + Inches(0.1), Inches(7.6), Inches(0.72),
         [(d, 12.5, GREY)], anchor=MSO_ANCHOR.MIDDLE)
    yy += Inches(1.02)
footer(s, 7)


# ================================================================ SLIDE 8 — Unique features
s = slide()
header(s, "Differentiators", "Features no rival ships in one product", GREEN)
feats = [
    ("🤖", "AI / ML built-in", "Isolation-Forest anomaly detection + transformer payload "
     "classifier (<2 ms). Catches obfuscated & zero-day attacks rules miss."),
    ("💬", "LLM rule copilot", "Explains alerts in plain English, writes new rules from your "
     "own logs, and generates virtual patches from CVE descriptions."),
    ("🧩", "WASM plugins", "Extend the WAF in Rust, Go, AssemblyScript or JS. Hot-swap in "
     "production — zero restart, sandboxed with capability grants."),
    ("📤", "Egress DLP", "Scans RESPONSES for PII, secrets, API keys and credit cards. "
     "ModSecurity / Coraza / BunkerWeb are inbound-only."),
    ("🔐", "HTTP/3 + Post-Quantum TLS", "QUIC via quinn, plus X25519+Kyber768 hybrid crypto — "
     "quantum-safe today."),
    ("🔌", "GraphQL & gRPC firewall", "Schema validation, depth/complexity limits, per-method "
     "rate limits, field-level DLP."),
    ("🌐", "Raft active/active HA", "True multi-master clustering — no CARP/VRRP, no SPOF, no "
     "active-standby failover gap."),
    ("📊", "OpenTelemetry native", "Traces, metrics and logs out of the box — plug straight "
     "into your existing SOC / observability stack."),
]
cw = Inches(6.05); ch = Inches(1.14); gx = Inches(0.18); gy = Inches(0.16)
x0, y0 = Inches(0.55), Inches(1.65)
for i, (ic, t, d) in enumerate(feats):
    col = i % 2; row = i // 2
    x = x0 + col * (cw + gx); y = y0 + row * (ch + gy)
    box(s, x, y, cw, ch, fill=PANEL, line=GREEN, lw=0.75)
    text(s, x + Inches(0.12), y + Inches(0.16), Inches(0.8), Inches(0.8),
         [(ic, 26, GREEN)], align=PP_ALIGN.CENTER)
    text(s, x + Inches(0.95), y + Inches(0.12), cw - Inches(1.1), Inches(0.4),
         [(t, 14.5, WHITE, True)])
    text(s, x + Inches(0.95), y + Inches(0.46), cw - Inches(1.15), Inches(0.6),
         [(d, 11, GREY)])
footer(s, 8)


# ================================================================ SLIDE 9 — Benchmarks
s = slide()
header(s, "Proof · Performance", "Hard numbers, measured", CYAN)
chips9 = [("40 µs", "clean-request scan (200 rules)", CYAN),
          ("505 ns", "block an attacker", GREEN),
          ("Linear O(n)", "rule scaling, no cliff", BLUE),
          ("Flat p99", "no GC, std-dev < 1 µs", ORANGE)]
x = Inches(0.55)
for v, l, c in chips9:
    chip(s, x, Inches(1.65), Inches(3.0), Inches(1.05), l, v, c)
    x += Inches(3.05)

# table: speed multipliers
rows = [
    ("Sentinel is faster than…", "Rule inspection", "Block attacker", "Total pipeline"),
    ("ModSecurity", "25–125×", "~2,000×", "10–40×"),
    ("Coraza (best OSS)", "5–12×", "~100×", "4–7×"),
    ("BunkerWeb (Lua/Nginx)", "10–60×", "~300×", "8–30×"),
    ("Cloudflare WAF", "5–50×", "~400×", "2–25×"),
    ("AWS WAF", "12–75×", "~1,000×", "5–25×"),
]
tL, tT, tW = Inches(0.55), Inches(3.05), Inches(12.27)
rh = Inches(0.5); cw0 = Inches(4.5)
cwn = (tW - cw0) / 3
for ri, row in enumerate(rows):
    yy = tT + rh * ri
    head = ri == 0
    fill = PANEL2 if head else (PANEL if ri % 2 else RGBColor(0x10,0x1A,0x2D))
    box(s, tL, yy, tW, rh, fill=fill, rounded=False)
    text(s, tL + Inches(0.18), yy, cw0 - Inches(0.2), rh,
         [(row[0], 12.5, CYAN if head else WHITE, head)], anchor=MSO_ANCHOR.MIDDLE)
    for ci in range(1, 4):
        cx = tL + cw0 + cwn * (ci - 1)
        col = CYAN if head else GREEN
        text(s, cx, yy, cwn, rh, [(row[ci], 12.5, col if not head else CYAN, True)],
             align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)
text(s, Inches(0.55), Inches(6.62), Inches(12.2), Inches(0.6),
     [("Sentinel figures measured in-house (Criterion.rs, release build, 200-rule policy). "
       "Multipliers are computed against competitors' published / community-reported latencies — "
       "directional, not identical-hardware head-to-head. Next slide: exact method.",
       11, GREY, False, True)])
footer(s, 9)


# ================================================================ SLIDE 10 — Methodology
s = slide()
header(s, "Proof · Methodology", "How we got these numbers", BLUE)
text(s, Inches(0.55), Inches(1.6), Inches(12.2), Inches(0.5),
     [("Every Sentinel figure is reproducible from this repository — not a marketing estimate. "
       "Here is exactly what we ran.", 13.5, GREY)])

methods = [
    ("⏱  40 µs / 505 ns / 71×", CYAN,
     "Criterion.rs statistical micro-benchmark (crates/sentinel-rules/benches/vm_bench.rs), "
     "release build. 200 compiled rules; clean vs malicious payload; early-exit threshold = 5. "
     "Criterion runs thousands of iterations and reports mean + std-dev.",
     "cargo bench -p sentinel-rules"),
    ("📈  Linear O(n) scaling", BLUE,
     "Same harness re-run at 50 / 100 / 200 / 500 rules. Latency rose 10 → 22 → 40 → 106 µs — "
     "arithmetic, no quadratic cliff, std-dev < 1 µs (flat p99, no GC jitter).",
     "vm_varying_rule_counts benchmark group"),
    ("✅  300+ Rust + 23 Go tests", GREEN,
     "Unit + integration + e2e + evasion + fuzz suites. Grew from 226 (audit baseline) to 348 "
     "at report time; the tree carries even more today — all passing, zero failures.",
     "cargo nextest run --workspace   ·   go test ./..."),
    ("🛡  Attack & evasion coverage", ORANGE,
     "Live proxy→WAF→upstream tests block SQLi, XSS, LFI, RCE, SSRF, Log4Shell + double/triple "
     "URL-encode, unicode, null-byte, CRLF, request-smuggling (CL.TE / TE.CL / TE.TE). "
     "Parsers fuzzed so they never panic on hostile input.",
     "tests/integration · tests/security · tests/fuzz"),
]
yy = Inches(2.3)
for t, c, d, cmd in methods:
    box(s, Inches(0.55), yy, Inches(12.27), Inches(1.02), fill=PANEL)
    box(s, Inches(0.55), yy, Inches(0.12), Inches(1.02), fill=c, rounded=False)
    text(s, Inches(0.95), yy + Inches(0.1), Inches(3.6), Inches(0.85),
         [(t, 15, c, True)], anchor=MSO_ANCHOR.MIDDLE)
    text(s, Inches(4.7), yy + Inches(0.09), Inches(7.9), Inches(0.62), [(d, 11.5, GREY)])
    text(s, Inches(4.7), yy + Inches(0.72), Inches(7.9), Inches(0.28),
         [(cmd, 10.5, CYAN, False, True)])
    yy += Inches(1.12)
footer(s, 10)


# ================================================================ SLIDE 11 — Feature matrix
s = slide()
header(s, "Proof · Capability", "Sentinel vs the field", BLUE)
cols = ["Capability", "Sentinel", "Coraza", "ModSec", "BunkerWeb", "Cloud WAF"]
data = [
    ("OWASP CRS rules",        "✔", "✔", "✔", "✔", "~"),
    ("Compiled bytecode VM",   "✔", "✘", "✘", "✘", "?"),
    ("Early-exit blocking",    "✔", "✘", "✘", "✘", "✘"),
    ("Inline ML / anomaly",    "✔", "✘", "✘", "✘", "~"),
    ("LLM rule copilot",       "✔", "✘", "✘", "✘", "✘"),
    ("eBPF/XDP kernel DDoS",   "✔", "✘", "✘", "✘", "~"),
    ("Egress DLP",             "✔", "✘", "✘", "✘", "~"),
    ("WASM plugins (any lang)","✔", "~", "✘", "✘", "~"),
    ("Post-quantum TLS",       "✔", "✘", "✘", "✘", "~"),
    ("Active/active Raft HA",  "✔", "~", "~", "~", "✔"),
    ("Self-host / data sovereign","✔","✔","✔","✔","✘"),
]
tL, tT, tW = Inches(0.55), Inches(1.6), Inches(12.27)
ncol = len(cols)
c0 = Inches(4.0)
cwn = (tW - c0) / (ncol - 1)
rh = Inches(0.43)
# header row
box(s, tL, tT, tW, rh, fill=PANEL2, rounded=False)
text(s, tL + Inches(0.15), tT, c0 - Inches(0.2), rh, [(cols[0], 12.5, CYAN, True)],
     anchor=MSO_ANCHOR.MIDDLE)
for ci in range(1, ncol):
    cx = tL + c0 + cwn * (ci - 1)
    col = CYAN if ci == 1 else GREY
    text(s, cx, tT, cwn, rh, [(cols[ci], 12, col, True)], align=PP_ALIGN.CENTER,
         anchor=MSO_ANCHOR.MIDDLE)
for ri, row in enumerate(data):
    yy = tT + rh * (ri + 1)
    fill = PANEL if ri % 2 else RGBColor(0x10,0x1A,0x2D)
    box(s, tL, yy, tW, rh, fill=fill, rounded=False)
    text(s, tL + Inches(0.15), yy, c0 - Inches(0.2), rh, [(row[0], 11.5, WHITE)],
         anchor=MSO_ANCHOR.MIDDLE)
    for ci in range(1, ncol):
        cx = tL + c0 + cwn * (ci - 1)
        v = row[ci]
        c = GREEN if v == "✔" else (RED if v == "✘" else (ORANGE if v == "~" else DGREY))
        text(s, cx, yy, cwn, rh, [(v, 13, c, True)], align=PP_ALIGN.CENTER,
             anchor=MSO_ANCHOR.MIDDLE)
text(s, Inches(0.55), Inches(6.95), Inches(12), Inches(0.3),
     [("✔ built-in     ~ partial / add-on / enterprise-tier     ✘ not available     "
       "(competitor columns from public product docs)", 11, GREY)])
footer(s, 11)


# ================================================================ SLIDE 12 — Business value
s = slide()
header(s, "Business Value", "Why this matters for ESDS & clients", GREEN)
# left: pricing models (real public pricing)
box(s, Inches(0.55), Inches(1.65), Inches(6.0), Inches(3.55), fill=PANEL, line=GREEN, lw=1.2)
text(s, Inches(0.8), Inches(1.76), Inches(5.5), Inches(0.4),
     [("Pricing model — public list pricing", 15, GREEN, True)])
price = [
    ("Sentinel", "Under evaluation — TBD", CYAN),
    ("ModSecurity", "Open-source · $0 license", GREY),
    ("Coraza", "Open-source · $0 license", GREY),
    ("Cloudflare WAF", "Pro $20 / Business $200 per mo; Ent. custom", GREY),
    ("AWS WAF", "$5/ACL + $1/rule per mo + $0.60 / 1M req", GREY),
]
yy = Inches(2.28)
for name, val, c in price:
    text(s, Inches(0.95), yy, Inches(2.4), Inches(0.5),
         [(name, 12.5, WHITE if c == CYAN else GREY, c == CYAN)], anchor=MSO_ANCHOR.MIDDLE)
    text(s, Inches(3.0), yy, Inches(3.4), Inches(0.5),
         [(val, 11, c, c == CYAN)], align=PP_ALIGN.RIGHT, anchor=MSO_ANCHOR.MIDDLE)
    yy += Inches(0.55)
text(s, Inches(0.8), Inches(5.02), Inches(5.55), Inches(0.18),
     [("OSS = $0 license; real cost = self-hosted compute + ops.", 9.5, DGREY, False, True)])

# left bottom: the "we will think" pricing frame
box(s, Inches(0.55), Inches(5.4), Inches(6.0), Inches(1.05), fill=PANEL2, line=CYAN, lw=1)
text(s, Inches(0.8), Inches(5.5), Inches(5.55), Inches(0.9),
     [("💡  Sentinel pricing: to be defined.", 13.5, CYAN, True),
      ("Self-hosted model means cost scales with hardware, not with "
       "per-request metering — final packaging under evaluation.", 11, WHITE)],
     anchor=MSO_ANCHOR.MIDDLE)

# right: business pillars
pillars = [
    ("🧮 Predictable economics", "Self-hosted: no per-request billing. Cost tracks hardware, "
     "not traffic — unlike AWS/Cloudflare metering that grows with every request."),
    ("🏛 Data sovereignty", "Everything stays on-prem. Critical for BFSI, RBI, IRDAI, "
     "GDPR — cloud WAFs route plaintext traffic off-network."),
    ("🚀 New ESDS markets", "An on-prem WAF that out-performs our own cloud WAF — opens "
     "BFSI, government & defence accounts cloud WAFs can't serve."),
    ("⏱ 5-minute onboarding", "Add a site in the dashboard → auto HTTPS via Let's Encrypt, "
     "config pushed to all nodes < 200 ms. One-command deploy."),
]
yy = Inches(1.65)
for t, d in pillars:
    box(s, Inches(6.78), yy, Inches(6.04), Inches(1.18), fill=PANEL)
    box(s, Inches(6.78), yy, Inches(0.1), Inches(1.18), fill=GREEN, rounded=False)
    text(s, Inches(7.0), yy + Inches(0.13), Inches(5.7), Inches(0.35), [(t, 13.5, GREEN, True)])
    text(s, Inches(7.0), yy + Inches(0.5), Inches(5.65), Inches(0.62), [(d, 11, GREY)])
    yy += Inches(1.27)
footer(s, 12)


# ================================================================ SLIDE 13 — Summary
s = slide()
box(s, 0, 0, Inches(0.16), SH, fill=CYAN, rounded=False)
box(s, 0, SH - Inches(0.16), SW, Inches(0.16), fill=CYAN, rounded=False)
text(s, Inches(0.7), Inches(0.7), Inches(12), Inches(0.4), [("THE BOTTOM LINE", 14, CYAN, True)])
text(s, Inches(0.66), Inches(1.05), Inches(12), Inches(1.2),
     [("Not a better WAF —", 38, WHITE, True),
      ("what a WAF looks like when you build it in 2026, not 2002.", 26, CYAN, False, True)])
pts = [
    ("5–125× faster", "than any open-source or commercial WAF, with flat p99 latency.", CYAN),
    ("AI-native + kernel-deep", "ML detection, LLM copilot, eBPF/XDP DDoS, egress DLP — built in.", GREEN),
    ("Predictable to run", "no per-request metering, full data sovereignty, runs anywhere.", ORANGE),
    ("Production-proven", "300+ tests passing, fuzz-hardened parsers, evasion-resistant.", BLUE),
]
yy = Inches(2.85)
for t, d, c in pts:
    box(s, Inches(0.7), yy, Inches(11.9), Inches(0.72), fill=PANEL)
    box(s, Inches(0.7), yy, Inches(0.12), Inches(0.72), fill=c, rounded=False)
    text(s, Inches(1.0), yy + Inches(0.16), Inches(3.4), Inches(0.4), [(t, 17, c, True)])
    text(s, Inches(4.5), yy + Inches(0.06), Inches(8.0), Inches(0.6),
         [(d, 13.5, WHITE)], anchor=MSO_ANCHOR.MIDDLE)
    yy += Inches(0.82)
box(s, Inches(0.7), Inches(6.25), Inches(11.9), Inches(0.7), fill=CYAN)
text(s, Inches(0.7), Inches(6.34), Inches(11.9), Inches(0.5),
     [("Phases 0–5 complete · Phase 6 (HTTP/3, PQ-TLS, GraphQL/gRPC FW) in progress · v1.0 GA targeted",
       13.5, BG, True)], align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)

OUT = "/home/ayush3750/waf-development/Sentinel_WAF_Overview.pptx"
prs.save(OUT)
print("Saved:", OUT, "slides:", len(prs.slides._sldIdLst))
