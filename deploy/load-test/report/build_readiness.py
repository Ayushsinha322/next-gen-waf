# -*- coding: utf-8 -*-
"""Two-page production-readiness assessment for Swaraj Kavach."""
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
st.font.name = BODY_FONT; st.font.size = Pt(8.6); st.font.color.rgb = INK2
st.paragraph_format.space_after = Pt(4); st.paragraph_format.line_spacing = 1.16
rf = st.element.rPr.rFonts
for a in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"): rf.set(qn(a), BODY_FONT)

s0 = doc.sections[0]
s0.page_width, s0.page_height = Cm(21.0), Cm(29.7)
s0.top_margin, s0.bottom_margin = Cm(1.15), Cm(0.9)
s0.left_margin, s0.right_margin = Cm(1.3), Cm(1.3)
s0.header_distance, s0.footer_distance = Cm(0.7), Cm(0.55)
TW = 21.0 - 2.6

def P(text="", size=8.6, color=INK2, bold=False, italic=False,
      before=0, after=4, align=None, line=1.16):
    p = doc.add_paragraph(); no_space(p, before, after, line)
    if align: p.alignment = align
    if text: set_font(p.add_run(text), BODY_FONT, size, color, bold, italic)
    return p

def RICH(parts, size=8.6, before=0, after=4, line=1.16):
    p = doc.add_paragraph(); no_space(p, before, after, line)
    for t in parts:
        col = t[2] if len(t) > 2 else INK2
        set_font(p.add_run(t[0]), BODY_FONT, size, col, t[1])
    return p

def H(text, before=8, after=3):
    p = doc.add_paragraph(); no_space(p, before, after); keep_with_next(p)
    set_font(p.add_run(text.upper()), BODY_FONT, 8.4, ACCENT, bold=True)
    hrule(p, "C9D2CF", 4); return p

def BUL(items, size=8.4):
    for it in items:
        p = doc.add_paragraph(); no_space(p, before=0, after=3, line=1.15)
        p.paragraph_format.left_indent = Cm(0.42)
        p.paragraph_format.first_line_indent = Cm(-0.42)
        set_font(p.add_run("▪  "), BODY_FONT, size, ACCENT, bold=True)
        for t in (it if isinstance(it, list) else [(it, False)]):
            col = t[2] if len(t) > 2 else INK2
            set_font(p.add_run(t[0]), BODY_FONT, size, col, t[1])

def bar(score):
    filled = int(round(score))
    return "█" * filled + "░" * (10 - filled)

# ============================================================ MASTHEAD ====
t = doc.add_table(rows=1, cols=2); t.autofit = False
lay = OxmlElement("w:tblLayout"); lay.set(qn("w:type"), "fixed"); t._tbl.tblPr.append(lay)
g = t._tbl.find(qn("w:tblGrid"))
for gc, w in zip(g.findall(qn("w:gridCol")), [11.5, 6.6]):
    gc.set(qn("w:w"), str(int(Cm(w).twips)))
L, R = t.cell(0, 0), t.cell(0, 1)
for c, w in ((L, 11.5), (R, 6.6)):
    c.width = Cm(w); cell_borders(c); cell_margins(c, 0, 30, 0, 0)
p = L.paragraphs[0]; no_space(p, after=0)
set_font(p.add_run("Swaraj Kavach"), BODY_FONT, 20, ACCENT, bold=True)
q = L.add_paragraph(); no_space(q, after=0)
set_font(q.add_run("Next-Generation Web Application Firewall"), BODY_FONT, 8.8, INK2)
q = L.add_paragraph(); no_space(q, before=3, after=0)
set_font(q.add_run("Production Readiness and Stability Assessment"), BODY_FONT, 11.5, INK, bold=True)
rp = R.paragraphs[0]; no_space(rp, after=0); rp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
set_font(rp.add_run("ESDS"), BODY_FONT, 12.5, ACCENT, bold=True)
for line in ("Research and Development", "Ayush Sinha", "",
             "Version 1.0  ·  9 September 2026",
             "Confidential — internal and executive distribution"):
    z = R.add_paragraph(); no_space(z, after=0, line=1.14)
    z.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    set_font(z.add_run(line), BODY_FONT, 7.0, MUTED)
hrule(P(after=5), "0A6A5C", 10)

# ---------------------------------------------------------- verdict box ---
callout(doc, "Verdict",
 [[("Approved for internal deployment.", True),
   (" One condition: run authentication paths in learning mode per site until the "
    "classifier defect in section 5 is remediated. Every other control is verified.", False)],
  [("Readiness rating ", False), ("8.9 of 10", True),
   (" on the single-tenant product-readiness scale, up from 8.8 recorded 31 July. "
    "The increment is small deliberately: three of the four evidence gaps recorded at "
    "8.8 are now closed, but the gating measurement — false-positive rate against "
    "real production traffic — remains unmeasured, and one precision defect was "
    "found during this period.", False)]])

# ================================================== 1. WHERE IT STANDS ====
H("1   Where the product stands", before=4)
table(doc, ["Dimension", "Score", "", "Basis"], [
 ["Attack detection", "9.0", bar(9.0),
  "99.64% composite; all 25 attack classes covered, none below 87.5%"],
 ["Throughput and latency", "9.0", bar(9.0),
  "7,595 legitimate and 7,870 blocked requests/second; absorbs 3,000 attacks/s with no loss"],
 ["Availability", "9.0", bar(9.0),
  "Three-node cluster, rolling upgrade verified, HTTPS multi-homed"],
 ["Observability", "8.8", bar(8.8),
  "Verifiable audit chain, SIEM feed, log redaction; 7 of 12 subsystems emit no log lines"],
 ["Product self-security", "8.5", bar(8.5),
  "All 4 launch criticals and 13 red-team findings closed; fails closed on rule-compile failure"],
 ["Packaging and install", "8.5", bar(8.5),
  "Offline bundle, installer proven end to end, upgrade and rollback paths"],
 ["Operational evidence", "7.5", bar(7.5),
  "46-hour run completed; install proven; competitive position measured"],
 ["Precision on real traffic", "6.5", bar(6.5),
  "The gate. Corpus-excellent, never measured on production traffic"],
], widths=[4.2, 1.4, 2.5, 10.3], align=["l", "c", "l", "l"], font=7.0, mono=False,
  col_colors={(7, 1): WARN, (7, 2): WARN},
  note="Scale: single-tenant product readiness, the scale all historical figures for this product "
       "use. The last two dimensions are evidence-bound, not code-bound: no further engineering "
       "raises them, only measurement against real traffic.")

# ================================================= 2. WHAT IS MEASURED ====
H("2   Evidence base")
table(doc, ["Property", "Status", "Figure"], [
 ["Attack detection breadth", "MEASURED", "99.64% composite; best rival arm 75.30%"],
 ["Competitive position", "MEASURED", "Ahead of SafeLine 9.4.1 and BunkerWeb 1.6.9, same-session"],
 ["Throughput, legitimate traffic", "MEASURED", "7,595 requests/second sustained"],
 ["Throughput, attack traffic", "MEASURED", "7,870 requests/second, no loss at 3,000/s"],
 ["Resource cost", "MEASURED", "131 MiB; 636 µs processor time per request"],
 ["Long-run stability", "MEASURED", "46 hours continuous, 542 samples, 132,486 requests inspected"],
 ["Installation, clean host", "MEASURED", "Completed end to end; cluster failover verified separately"],
 ["False-positive rate, real traffic", "NOT MEASURED", "The one gating gap. Requires a mirrored production stream"],
 ["Certificate issuance, live", "UNVERIFIED", "No record of a live issuance test; verify before customer use"],
], widths=[5.4, 2.5, 10.5], align=["l", "c", "l"], font=7.0, mono=False,
  col_colors={(7, 1): BAD, (7, 2): BAD, (8, 1): WARN, (8, 2): WARN})

# =============================================== 5. VERDICT BY SCENARIO ==
H("3   Readiness by deployment scenario")
table(doc, ["Scenario", "Verdict", "Reasoning"], [
 ["Internal ESDS sites", "READY",
  "All controls verified, 46-hour run clean, cluster and installer proven. Condition: authentication paths in learning mode until the classifier defect closes."],
 ["Dedicated stack per customer", "CONDITIONAL",
  "Engineering is ready. Gated on the false-positive pilot, because a customer-facing blocking deployment cannot rest on a corpus-measured precision figure."],
 ["Shared multi-tenant service", "OUT OF SCOPE",
  "Deliberate product decision: one dedicated stack per customer. Isolation is by separate deployment, not by database policy."],
], widths=[4.2, 2.5, 11.7], align=["l", "c", "l"], font=7.0, mono=False,
  col_colors={(0, 1): ACCENT, (1, 1): WARN, (2, 1): MUTED})

doc.add_page_break()

# ============================================ 3. THE STABILITY RUN =======
H("4   46-hour continuous stability run", before=0)
RICH([("Mixed legitimate and attack traffic through the load balancer to all three nodes, "
       "sampled every five minutes. Repeat-offender correlation was left ", False),
      ("enabled", True),
      (" so the run exercised the product as shipped, with attack sources rotated so the "
       "generator did not ban itself.", False)], size=8.4, after=4)

table(doc, ["Measure", "First half", "Second half", "Change", "Verdict"], [
 ["Data-plane memory", "137.2 MiB", "175.6 MiB", "+28.0%", "OPEN"],
 ["Control-plane memory", "25.7 MiB", "26.5 MiB", "+3.0%", "pass"],
 ["Open file descriptors, median", "28", "28", "no change", "pass"],
 ["Sites losing inspection coverage", "0", "0", "none", "pass"],
 ["Container restarts", "0", "0", "none", "pass"],
 ["Open alerts", "11 at start", "17 at end", "+6 raised", "pass"],
 ["Disk utilisation", "74%", "74%", "no change", "pass"],
 ["Log volume", "47 MB at start", "648 MB at end", "+601 MB", "action"],
], widths=[5.4, 2.5, 2.5, 2.3, 1.9], font=7.0, mono=False,
  align=["l", "r", "r", "r", "c"],
  col_colors={(0, 4): WARN, (7, 4): WARN})

figure(doc, FIG("soak-trend.png"),
       "Memory and descriptor behaviour across the full run. Three discrete 16 MiB increments "
       "sit on top of a gradual creep that decelerates from 0.37 to 0.11 MiB per hour. "
       "Descriptors return to their baseline of 28 after every excursion.", width_cm=13.6)

BUL([
 [("Descriptors did not leak, but they are not static either. ", True),
  ("The median is unchanged at 28 and every excursion returned to that baseline, with "
   "a peak of 81 and the longest excursion lasting 8.6 hours. Bounded and "
   "self-releasing, which is a pass, but not the flat line a summary figure alone "
   "would suggest.", False)],
 [("Memory grew 60.9 MiB after start-up, and this is the one open item. ", True),
  ("48.1 MiB is three discrete 16 MiB increments; 12.8 MiB is creep whose rate falls "
   "each quarter, consistent with caches filling rather than a leak. Only the first "
   "node grew, though all three served traffic to within three requests of each other. "
   "Two candidate causes were tested and eliminated: administrative-endpoint polling, "
   "and event-store write failures. The cause is not yet known.", False)],
 [("Nothing failed and nothing degraded. ", True),
  ("No restart, no loss of inspection coverage, no alert backlog, no disk pressure. At "
   "193 MiB against a 17 GiB allowance there is no operational risk at this scale.", False)],
])

# ============================================== 4. OPEN ITEMS ============
H("5   Open items and what each one gates")
table(doc, ["Item", "Severity", "Gates", "Position"], [
 ["False-positive rate against real traffic never measured", "Gating",
  "The readiness rating and any external precision claim",
  "Needs ~2 weeks of mirrored production traffic plus a week of triage. Not started."],
 ["Classifier rejects login forms carrying a persistent-session field", "High",
  "Blocking mode on authentication paths",
  "2 of 8 ordinary form submissions affected. Remediation is training-data coverage, not tuning."],
 ["Data-plane memory: three unexplained 16 MiB increments on one node", "Medium",
  "Nothing at present scale",
  "Two causes eliminated. Next test is correlation against control-plane activity."],
 ["Event-store write path failed 95 times in 46 hours", "Medium",
  "Confidence in the analytics path, not in enforcement",
  "Self-healed every time via spooling and replay. Cause is a per-query memory limit, not the container limit."],
 ["Log volume and retention", "Medium",
  "Capacity planning at production request rates",
  "649 MB after 46 hours at 3 requests/second, no rotation policy in force."],
 ["Live certificate issuance never tested", "Medium",
  "Customer deployments using automatic certificates",
  "No record of a live test. Verify before customer-facing deployment."],
], widths=[5.2, 1.8, 4.2, 7.2], align=["l", "c", "l", "l"], font=6.9, mono=False,
  col_colors={(0, 1): BAD, (1, 1): WARN})

hrule(P(after=3), "C9D2CF", 4)
RICH([("What separates 8.9 from a defensible 9.5 is not code: it is two weeks of mirrored "
       "production traffic and a measured false-positive rate. ", True),
      ("Swaraj Kavach build fb0e741 on the three-node cluster; competitive figures from build "
       "92e0d46. Stability run 7–9 September 2026, 46.4 hours, ended two hours early at "
       "operator request. Detection by GoTestWAF, load by vegeta. Supporting detail in the "
       "24-page comparative benchmark report.", False)], size=7.0, after=0)

out = os.path.join(HERE, "Swaraj-Kavach-Readiness-Assessment-v1.0.docx")
doc.save(out); print("saved:", out)
