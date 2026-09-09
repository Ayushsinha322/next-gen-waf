# -*- coding: utf-8 -*-
"""Standalone two-page continuous-stability (soak) test report."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Pt, Cm
from build_helpers import *

HERE = os.path.dirname(os.path.abspath(__file__))
FIG = lambda n: os.path.join(HERE, "figs", n)
doc = Document()
st = doc.styles["Normal"]
st.font.name = BODY_FONT; st.font.size = Pt(8.5); st.font.color.rgb = INK2
st.paragraph_format.space_after = Pt(4); st.paragraph_format.line_spacing = 1.15
rf = st.element.rPr.rFonts
for a in ("w:ascii","w:hAnsi","w:cs","w:eastAsia"): rf.set(qn(a), BODY_FONT)
s0 = doc.sections[0]
s0.page_width, s0.page_height = Cm(21.0), Cm(29.7)
s0.top_margin, s0.bottom_margin = Cm(1.15), Cm(0.9)
s0.left_margin, s0.right_margin = Cm(1.3), Cm(1.3)
s0.header_distance, s0.footer_distance = Cm(0.7), Cm(0.55)
TW = 21.0 - 2.6

def P(text="", size=8.5, color=INK2, bold=False, italic=False, before=0, after=4,
      align=None, line=1.15):
    p = doc.add_paragraph(); no_space(p, before, after, line)
    if align: p.alignment = align
    if text: set_font(p.add_run(text), BODY_FONT, size, color, bold, italic)
    return p
def RICH(parts, size=8.5, before=0, after=4, line=1.15):
    p = doc.add_paragraph(); no_space(p, before, after, line)
    for t in parts:
        col = t[2] if len(t) > 2 else INK2
        set_font(p.add_run(t[0]), BODY_FONT, size, col, t[1])
    return p
def H(text, before=8, after=3):
    p = doc.add_paragraph(); no_space(p, before, after); keep_with_next(p)
    set_font(p.add_run(text.upper()), BODY_FONT, 8.4, ACCENT, bold=True)
    hrule(p, "C9D2CF", 4); return p
def BUL(items, size=8.3):
    for it in items:
        p = doc.add_paragraph(); no_space(p, before=0, after=3, line=1.14)
        p.paragraph_format.left_indent = Cm(0.42)
        p.paragraph_format.first_line_indent = Cm(-0.42)
        set_font(p.add_run("▪  "), BODY_FONT, size, ACCENT, bold=True)
        for t in (it if isinstance(it, list) else [(it, False)]):
            col = t[2] if len(t) > 2 else INK2
            set_font(p.add_run(t[0]), BODY_FONT, size, col, t[1])

# ---------------------------------------------------------------- masthead
t = doc.add_table(rows=1, cols=2); t.autofit = False
lay = OxmlElement("w:tblLayout"); lay.set(qn("w:type"),"fixed"); t._tbl.tblPr.append(lay)
g = t._tbl.find(qn("w:tblGrid"))
for gc,w in zip(g.findall(qn("w:gridCol")), [11.6, 6.8]): gc.set(qn("w:w"), str(int(Cm(w).twips)))
L,R = t.cell(0,0), t.cell(0,1)
for c,w in ((L,11.6),(R,6.8)):
    c.width=Cm(w); cell_borders(c); cell_margins(c,0,30,0,0)
p=L.paragraphs[0]; no_space(p,after=0)
set_font(p.add_run("Swaraj Kavach"), BODY_FONT, 20, ACCENT, bold=True)
q=L.add_paragraph(); no_space(q,after=0)
set_font(q.add_run("Next-Generation Web Application Firewall"), BODY_FONT, 8.8, INK2)
q=L.add_paragraph(); no_space(q,before=3,after=0)
set_font(q.add_run("Continuous Stability Test Report"), BODY_FONT, 11.5, INK, bold=True)
rp=R.paragraphs[0]; no_space(rp,after=0); rp.alignment=WD_ALIGN_PARAGRAPH.RIGHT
set_font(rp.add_run("ESDS"), BODY_FONT, 12.5, ACCENT, bold=True)
for line in ("Research and Development","Ayush Sinha","",
             "Version 1.0  ·  9 September 2026",
             "Confidential — internal and executive distribution"):
    z=R.add_paragraph(); no_space(z,after=0,line=1.13)
    z.alignment=WD_ALIGN_PARAGRAPH.RIGHT
    set_font(z.add_run(line), BODY_FONT, 7.0, MUTED)
hrule(P(after=5), "0A6A5C", 10)

callout(doc, "Result",
 [[("PASS, with one item left open.", True),
   (" Over 46 continuous hours the product inspected 132,486 requests and refused "
    "13,160 of them with no container restart, no loss of inspection coverage on any "
    "node, no descriptor leak and no disk pressure.", False)],
  [("The open item is data-plane memory, which rose 60.9 MiB on one of three nodes. "
    "Two candidate causes were tested and eliminated; the cause is not yet known. At "
    "193 MiB against a 17 GiB container allowance it presents no operational risk at "
    "this scale, and it should be explained before a long-lived production deployment.", False)]])

# =============================================================== 1. DESIGN
H("1   Test design", before=4)
table(doc, ["Parameter","Setting","Why this way"], [
 ["Duration and sampling","46 hours, 14 measures every 5 minutes, 542 samples",
  "48 planned; stopped two hours early once the trends were established. A trend, not a snapshot"],
 ["Traffic","Mixed legitimate and attack, ~3 requests/second",
  "A flood measures throughput, measured elsewhere. A soak measures whether the product survives"],
 ["Path","Load balancer to all three nodes",
  "Exercises the balancer, all three data planes and the origin, not one process in isolation"],
 ["Repeat-offender correlation","LEFT ENABLED",
  "A soak that switches off a control to keep its own traffic flowing is not soaking the product"],
 ["Attack sources","Rotated per request",
  "So the generator does not trip the auto-ban and silence itself, while the ban logic still runs"],
], widths=[4.1,4.6,9.7], align=["l","l","l"], font=7.1, mono=False)

# ============================================================== 2. RESULTS
H("2   Results")
RICH([("Two kinds of measure need two kinds of comparison: ", True),
      ("stationary series are judged by whether the second half's median differs from the "
       "first, cumulative counters by their first and last readings, because a median of a "
       "rising counter means nothing.", False)], size=8.3, after=4)

table(doc, ["Measure","At start / first half","At end / second half","Change","Verdict"], [
 ["Stationary series — median of first half against second","","","",""],
 ["Data-plane memory","137.2 MiB","175.6 MiB","+28.0%","OPEN"],
 ["Control-plane memory","25.7 MiB","26.5 MiB","+3.0%","pass"],
 ["Open file descriptors, median","28","28","no change","pass"],
 ["Probe latency, p50","30.3 ms","34.5 ms","+13.9%","attributed"],
 ["Disk utilisation","74%","74%","no change","pass"],
 ["Cumulative counters — first reading against last","","","",""],
 ["Requests inspected","6","132,486","+132,480","—"],
 ["Requests refused","0","13,160","+13,160","—"],
 ["Log volume","47 MB","648 MB","+601 MB","action"],
 ["Open alerts","11","17","+6","pass"],
 ["Coverage losses and restarts","0","0","none at any sample","pass"],
], widths=[5.4,3.1,3.1,2.6,2.2], align=["l","r","r","r","c"], font=7.2, mono=False,
  group_rows=(0,6), col_colors={(1,4):WARN,(4,4):MUTED,(9,4):WARN})

doc.add_page_break()

figure(doc, FIG("soak-trend.png"),
       "Memory and descriptors across the full window. Three discrete 16 MiB increments sit "
       "on a gradual creep that decelerates. Descriptors return to a baseline of 28 after "
       "every excursion.", width_cm=10.6)

# ========================================================= 3. THE OPEN ITEM
H("3   The open item: data-plane memory", before=0)
RICH([("Only the first of the three nodes grew. ", True),
      ("It finished at 193.1 MiB against 138.1 and 143.6 on the other two, which served "
       "traffic to within three requests of each other over the whole run. Identical load, "
       "different outcome, so load is not the explanation.", False)], size=8.3, after=4)

table(doc, ["Component of the 60.9 MiB rise","Amount","Character"], [
 ["Three discrete increments, 16.0 / 16.1 / 16.0 MiB","48.1 MiB",
  "At 09:23 and 13:23 on 8 Sept and 02:38 on 9 Sept. A repeating fixed quantum with flat plateaus between, which is the signature of the allocator claiming an arena and not returning it"],
 ["Gradual creep within the plateaus","12.8 MiB",
  "Rate decays 0.37 then 0.25 then 0.15 then 0.12 MiB per hour across successive plateaus, consistent with caches filling rather than a leak"],
], widths=[6.2,2.2,10.0], align=["l","r","l"], font=7.2, mono=False)

H("Causes tested and eliminated")
table(doc, ["Hypothesis","Test","Result"], [
 ["Administrative-endpoint polling — the only node the samplers poll, ~1,000 extra requests over the run",
  "30,000 requests to the health and metrics endpoints of a throwaway container from the same image, no proxied traffic",
  "ELIMINATED — one 7 MiB step in the first 5,000 requests then flat for 25,000 more. A control arm of 30,000 inspected requests behaved identically. Neither path grows per request"],
 ["Event-store write failures — the third increment sits beside a store memory-limit error and a spool-and-reconnect",
  "Compare failure and spool-replay counts across the three nodes",
  "ELIMINATED — the second node logged 95 flush failures and 201 spool replays against this node's 95 and 200, and did not grow at all"],
], widths=[5.8,4.4,8.2], align=["l","l","l"], font=6.9, mono=False,
  col_colors={(0,2):ACCENT,(1,2):ACCENT})
RICH([("What remains. ", True),
      ("The only difference found between this node and the other two is that it holds "
       "sixteen persistent connections to the control plane while they hold none. "
       "Correlating the increment timestamps against control-plane activity is the next "
       "test, and needs no further elapsed time.", False)], size=8.3, after=4)

# ============================================= 4. SECONDARY OBSERVATIONS
H("4   Secondary observations")
BUL([
 [("Descriptors did not leak, and they are not static either. ", True),
  ("Median unchanged at 28, and exactly 28 in 60% of samples, but with five excursions "
   "peaking at 81 and one lasting 8.6 hours. Every excursion returned to baseline. "
   "Bounded and self-releasing, so a pass, but a summary figure alone would have "
   "described a flat line that does not exist.", False)],
 [("Latency: the rise is not the firewall. ", True),
  ("The probe's end-to-end median rose 13.9%, but the firewall's own accounting of the "
   "share of requests served under 10, 25 and 50 milliseconds is flat to marginally "
   "improving quarter on quarter. The rise sits in the probe path and the demo origin. "
   "Attributed, not eliminated.", False)],
 [("The event-store write path failed 104 times and recovered every time. ", True),
  ("95 traffic-batch and 9 event-batch failures, 113 reconnections, 200 spool replays. "
   "Enforcement is unaffected: inspection does not depend on the analytics write. Cause "
   "is a per-query memory limit inside the store, not the container allowance at 21% of "
   "6 GB. Six alerts were raised over the run, 11 to 17, with no backlog.", False)],
])

# ========================================================== 5. CONCLUSIONS
H("5   Conclusion and next actions")
table(doc, ["Next action","Priority","Effort"], [
 ["Correlate the three memory increments against control-plane activity","High","Hours, on data already collected"],
 ["Decide a log retention and rotation policy","High","A configuration decision"],
 ["Raise the event-store per-query memory limit and re-measure the write path","Medium","Configuration change plus one run"],
 ["Repeat the run at production request rates once a real workload exists","Medium","Blocked on the false-positive pilot"],
], widths=[9.2,2.2,6.8], align=["l","c","l"], font=7.2, mono=False)

hrule(P(after=3), "C9D2CF", 4)
RICH([("Window 2026-09-07 10:38:34Z to 2026-09-09 08:35:38Z, 46.0 hours, 542 samples at "
       "five-minute intervals, build fb0e741 on the three-node cluster. The sampler ran on "
       "past the generator stop; nine later samples are excluded throughout. Raw samples "
       "and analysis scripts accompany this report.", False)], size=7.0, after=0)

out = os.path.join(HERE, "Swaraj-Kavach-Stability-Test-Report-v1.0.docx")
doc.save(out); print("saved:", out)
