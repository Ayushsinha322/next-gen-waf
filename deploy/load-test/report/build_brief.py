# -*- coding: utf-8 -*-
"""Two-page executive summary of the Swaraj Kavach benchmark."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Pt, Cm
from build_helpers import *
import content as C

HERE = os.path.dirname(os.path.abspath(__file__))
FIG = lambda n: os.path.join(HERE, "figs", n)
M = C.META
doc = Document()

st = doc.styles["Normal"]
st.font.name = BODY_FONT; st.font.size = Pt(8.8); st.font.color.rgb = INK2
st.paragraph_format.space_after = Pt(4); st.paragraph_format.line_spacing = 1.18
rf = st.element.rPr.rFonts
for a in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"): rf.set(qn(a), BODY_FONT)

s0 = doc.sections[0]
s0.page_width, s0.page_height = Cm(21.0), Cm(29.7)
s0.top_margin, s0.bottom_margin = Cm(1.35), Cm(1.15)
s0.left_margin, s0.right_margin = Cm(1.55), Cm(1.55)
s0.header_distance, s0.footer_distance = Cm(0.7), Cm(0.6)
TW = 21.0 - 3.10          # usable text width in cm

def P(text="", size=8.8, color=INK2, bold=False, italic=False,
      before=0, after=4, align=None, font=BODY_FONT, line=1.18):
    p = doc.add_paragraph(); no_space(p, before, after, line)
    if align: p.alignment = align
    if text: set_font(p.add_run(text), font, size, color, bold, italic)
    return p

def RICH(parts, size=8.8, before=0, after=4, line=1.18):
    p = doc.add_paragraph(); no_space(p, before, after, line)
    for t in parts:
        col = t[2] if len(t) > 2 else INK2
        set_font(p.add_run(t[0]), BODY_FONT, size, col, t[1])
    return p

def H(text, before=8, after=3):
    p = doc.add_paragraph(); no_space(p, before, after); keep_with_next(p)
    set_font(p.add_run(text.upper()), BODY_FONT, 8.6, ACCENT, bold=True)
    hrule(p, "C9D2CF", 4)
    return p

def BUL(items, size=8.6):
    for it in items:
        p = doc.add_paragraph(); no_space(p, before=0, after=3, line=1.16)
        p.paragraph_format.left_indent = Cm(0.42)
        p.paragraph_format.first_line_indent = Cm(-0.42)
        set_font(p.add_run("▪  "), BODY_FONT, size, ACCENT, bold=True)
        for t in (it if isinstance(it, list) else [(it, False)]):
            col = t[2] if len(t) > 2 else INK2
            set_font(p.add_run(t[0]), BODY_FONT, size, col, t[1])

# ============================================================ MASTHEAD ====
t = doc.add_table(rows=1, cols=2)
t.autofit = False
lay = OxmlElement("w:tblLayout"); lay.set(qn("w:type"), "fixed"); t._tbl.tblPr.append(lay)
grid = t._tbl.find(qn("w:tblGrid"))
for gc, w in zip(grid.findall(qn("w:gridCol")), [11.4, 6.5]):
    gc.set(qn("w:w"), str(int(Cm(w).twips)))
L, R = t.cell(0, 0), t.cell(0, 1)
for c, w in ((L, 11.4), (R, 6.5)):
    c.width = Cm(w); cell_borders(c); cell_margins(c, 0, 40, 0, 0)
p = L.paragraphs[0]; no_space(p, after=0)
set_font(p.add_run("Swaraj Kavach"), BODY_FONT, 21, ACCENT, bold=True)
p = L.add_paragraph(); no_space(p, after=0)
set_font(p.add_run("Next-Generation Web Application Firewall"), BODY_FONT, 9, INK2)
p = L.add_paragraph(); no_space(p, before=3, after=0)
set_font(p.add_run("Comparative Security and Performance Benchmark"), BODY_FONT, 11.5, INK, bold=True)

rp = R.paragraphs[0]; no_space(rp, after=0); rp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
set_font(rp.add_run("ESDS"), BODY_FONT, 13, ACCENT, bold=True)
for line in ("Research and Development", "Ayush Sinha",
             "", "Version 1.0  ·  8 September 2026",
             "Confidential — customer and executive distribution"):
    q = R.add_paragraph(); no_space(q, after=0, line=1.16)
    q.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    set_font(q.add_run(line), BODY_FONT, 7.2, MUTED)
hrule(P(after=5), "0A6A5C", 10)

RICH([("ESDS measured ", False), ("Swaraj Kavach", True),
      (" against the two most widely deployed free web application firewalls, "
       "BunkerWeb 1.6.9 and SafeLine 9.4.1. All three ran in one continuous session on "
       "the same hardware, in front of the same origin server, against the same "
       "industry attack corpus, with no processor or memory limit applied to any of "
       "them. No figure is quoted from a vendor; nothing has been excluded.", False)],
     size=9.2, after=6)

# ================================================== SECURITY EFFECTIVENESS
H("1   Security effectiveness", before=2)
table(doc, ["Product and configuration", "Composite", "Attacks\nblocked",
            "API attacks", "Legitimate\nallowed", "Legitimate\nblocked"],
      C.DETECT_HEAD["rows"],
      widths=[6.0, 2.0, 2.0, 2.0, 2.0, 2.0], font=7.6, ours_rows=(0,),
      col_colors={(0,1):ACCENT,(0,2):ACCENT,(1,4):ACCENT,(1,5):ACCENT,
                  (4,4):BAD,(4,5):BAD})
figure(doc, FIG("brief-detection.png"), "", width_cm=TW)

BUL([
 [("Coverage is the decisive difference, and it is structural. ", True),
  ("Swaraj Kavach detects every attack class in the corpus, with no class below 87.5 "
   "per cent. SafeLine records ", False),
  ("zero detection across five complete classes", True),
  (" — LDAP injection, mail header injection, XML injection, CRLF injection and "
   "server-side includes, 86 payloads — at every available setting, because its "
   "engine has no module for them. No configuration change reaches that gap.", False)],
 [("Neither competitor has a usable maximum. ", True),
  ("BunkerWeb raised to maximum sensitivity detects 74.0 per cent of attacks and also "
   "rejects all 141 legitimate requests, so the setting cannot be deployed. Between "
   "its two settings there is no point that is both protective and usable.", False)],
 [("SafeLine is the more precise product, and this is stated plainly. ", True),
  ("It rejected none of the 141 legitimate requests at its shipped settings, against "
   "one for Swaraj Kavach, and it detects one SQL-injection payload we do not, 48 of "
   "48 against our 47.", False)],
])

callout(doc, "Bottom line",
 [[("The competitive question is not whether Swaraj Kavach is faster. It is whether a "
    "commercial product can justify itself against capable free alternatives.", True)],
  [("It can, on one specific and measurable basis: ", False),
   ("the free products each protect a subset of the attack surface and cannot be "
    "configured to protect the rest", True),
   (". SafeLine is precise but structurally narrow. BunkerWeb is broad but has no "
    "deployable sensitivity setting. Swaraj Kavach is the only product tested that is "
    "simultaneously broad, precise enough for production, and stable under attack "
    "load.", False)]])

# =============================================================== PAGE 2 ===
doc.add_page_break()

H("2   Performance", before=0)
table(doc, ["Target", "Legitimate\nthroughput", "99th pct\nlatency",
            "Attack\nblock rate", "Refusal\nsize", "Lost at 3,000\nattacks/s"], [
 ["Swaraj Kavach", "7,595 /s", "16.3 ms", "7,870 /s", "125 B", "none"],
 ["SafeLine, shipped defaults", "6,006 /s", "14.6 ms", "4,573 /s", "15,604 B", "none"],
 ["SafeLine, all modules strict", "4,688 /s", "22.9 ms", "4,054 /s", "15,604 B", "none"],
 ["BunkerWeb PL1, as shipped", "2,000 /s", "94.4 ms", "376 /s", "69,283 B", "13,073 of 45,000"],
 ["BunkerWeb PL1, refusal page reduced", "—", "—", "1,541 /s", "146 B", "4,672 of 45,000"],
 ["Origin server with no WAF", "32,190 /s", "4.79 ms", "—", "—", "—"],
], widths=[5.4, 2.4, 2.1, 2.2, 2.0, 3.0], font=7.6, ours_rows=(0,),
  col_colors={(3,5):BAD,(4,5):BAD},
  note="Refusal size is shown because it, rather than the inspection engine, dominates "
       "block-rate measurements: the three products differ by a factor of 554. SafeLine's "
       "refusal page cannot be reduced in the Community edition. BunkerWeb's can, and that "
       "arm is listed separately.")

BUL([
 [("Only Swaraj Kavach and SafeLine survive an attack flood. ", True),
  ("At a sustained 3,000 attacks per second Swaraj Kavach refused all 45,000 requests "
   "at a 99th-percentile latency of 8.16 ms and SafeLine also held, more slowly. "
   "BunkerWeb stopped answering in both of its configurations.", False)],
 [("At ordinary attack rates the three engines are indistinguishable. ", True),
  ("At 1,000 attacks per second all three cleared 15,000 requests with no loss, and "
   "SafeLine at maximum sensitivity was marginally the fastest. Separation appears "
   "only at 3,000 per second.", False)],
])

H("3   Cost to operate")
table(doc, ["Target", "Processor time per\nlegitimate request",
            "Processor time per\nrefused request", "Peak memory", "Deployment"], [
 ["Swaraj Kavach", "636 µs", "648 µs", "131 MiB", "single process"],
 ["SafeLine, inspection path", "419 µs", "724 µs", "349 MiB", "2 of 7 containers"],
 ["SafeLine, complete product", "559 µs", "989 µs", "1,381 MiB", "7 containers"],
 ["BunkerWeb", "2,918 µs", "41,518 µs", "993 MiB", "single container"],
], widths=[4.4, 3.6, 3.6, 2.6, 3.3], font=7.6, ours_rows=(0,),
  col_colors={(1,1):ACCENT,(0,2):ACCENT,(0,3):ACCENT,(3,1):BAD,(3,2):BAD},
  note="Identical load of 1,000 requests per second for 20 seconds against every target. "
       "Container processor time is read from the operating system control group and covers "
       "every process inside; Swaraj Kavach is a single native process read from the "
       "kernel's own counters. Time per request is divided by requests actually answered.")

BUL([
 [("Memory is 131 MiB and does not move. ", True),
  ("Identical on legitimate and attack traffic, at rest and under load — between 2.7 "
   "and 10.5 times leaner than either competitor. Part of that reflects deployment "
   "shape: we are one process, SafeLine ships seven containers.", False)],
 [("Cost per request barely changes when the product starts blocking, ", True),
  ("636 to 648 microseconds. SafeLine's processor cost rises 73 per cent under attack "
   "and BunkerWeb's rises fourteenfold. Predictable cost under attack is what makes "
   "capacity planning possible.", False)],
 [("SafeLine is about one third cheaper than us per legitimate request. ", True),
  ("This was attributed rather than assumed: two instances differing only in whether "
   "the machine-learning classifier was enabled cost 666 and 717 microseconds, so the "
   "classifier is not the cause. The cost is 350 compiled signatures evaluated on "
   "every request — the same mechanism that produces the coverage advantage above.", False)],
])

H("4   Disclosed limitations")
RICH([("Open defect. ", True),
      ("A legitimate login form carrying a persistent-session field is currently "
       "refused by the machine-learning classifier, which scores it above the blocking "
       "threshold on its own with no signature match. Two of eight ordinary form "
       "submissions tested are affected, both login forms. Remediation is a "
       "training-data change, scheduled after the current stability measurement; sites "
       "may run affected paths in monitoring mode meanwhile.", False)], after=3)
RICH([("A qualification on our own precision figure. ", True),
      ("The 141 legitimate requests in the industry corpus are plain text bodies, not "
       "form-encoded credential submissions, so the corpus cannot detect the defect "
       "above. The 99.29 per cent figure in section 1 is accurate with respect to the "
       "corpus and optimistic with respect to production traffic.", False)], after=3)
RICH([("Measurement scope. ", True),
      ("A single 16-thread host, loopback networking, no transport encryption. This is "
       "a reliable comparison between products under identical conditions, not a "
       "prediction of absolute throughput on customer hardware. No result here measures "
       "false-positive behaviour against real production traffic, which remains open "
       "work. API percentages rest on different denominators per product and are "
       "indicative only.", False)], after=5)

hrule(P(after=3), "C9D2CF", 4)
RICH([("Full 24-page report, per-class detection tables, all 22 load arms and the "
       "complete reproduction procedure are available on request. ", False),
      ("Build 92e0d46, internal engineering codename sentinel. "
       "GoTestWAF 675 attack and 141 legitimate payloads; vegeta 15-second runs, "
       "200 concurrent connections.", False)], size=7.2, after=0)

out = os.path.join(HERE, "Swaraj-Kavach-Benchmark-Summary-v1.0.docx")
doc.save(out)
print("saved:", out)
