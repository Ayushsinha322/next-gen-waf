# -*- coding: utf-8 -*-
"""Two-page side-by-side comparison: Swaraj Kavach vs SafeLine vs BunkerWeb."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Pt, Cm
from build_helpers import *

HERE = os.path.dirname(os.path.abspath(__file__))
doc = Document()

st = doc.styles["Normal"]
st.font.name = BODY_FONT; st.font.size = Pt(8.6); st.font.color.rgb = INK2
st.paragraph_format.space_after = Pt(4); st.paragraph_format.line_spacing = 1.16
rf = st.element.rPr.rFonts
for a in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"): rf.set(qn(a), BODY_FONT)

s0 = doc.sections[0]
s0.page_width, s0.page_height = Cm(21.0), Cm(29.7)
s0.top_margin, s0.bottom_margin = Cm(1.3), Cm(1.1)
s0.left_margin, s0.right_margin = Cm(1.4), Cm(1.4)
s0.header_distance, s0.footer_distance = Cm(0.7), Cm(0.6)
TW = 21.0 - 2.8                        # 18.2 cm usable
COLS = [5.0, 4.5, 4.4, 4.3]            # label + three products

OURS_COL = {1: SH_OURS}

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

HDR = ["", "Swaraj Kavach", "SafeLine 9.4.1", "BunkerWeb 1.6.9"]

def matrix(rows, caption=None, note=None, font=7.5, groups=(), winners=None,
           align=None):
    return table(doc, HDR, rows, widths=COLS,
                 align=align or ["l", "l", "l", "l"], font=font,
                 caption=caption, note=note, group_rows=groups,
                 col_colors=winners or {}, mono=False,
                 shade_cols=OURS_COL, bold_cols=(1,))

# ============================================================ MASTHEAD ====
t = doc.add_table(rows=1, cols=2); t.autofit = False
lay = OxmlElement("w:tblLayout"); lay.set(qn("w:type"), "fixed"); t._tbl.tblPr.append(lay)
g = t._tbl.find(qn("w:tblGrid"))
for gc, w in zip(g.findall(qn("w:gridCol")), [11.6, 6.6]):
    gc.set(qn("w:w"), str(int(Cm(w).twips)))
L, R = t.cell(0, 0), t.cell(0, 1)
for c, w in ((L, 11.6), (R, 6.6)):
    c.width = Cm(w); cell_borders(c); cell_margins(c, 0, 30, 0, 0)
p = L.paragraphs[0]; no_space(p, after=0)
set_font(p.add_run("Swaraj Kavach"), BODY_FONT, 20, ACCENT, bold=True)
q = L.add_paragraph(); no_space(q, after=0)
set_font(q.add_run("Next-Generation Web Application Firewall"), BODY_FONT, 8.8, INK2)
q = L.add_paragraph(); no_space(q, before=3, after=0)
set_font(q.add_run("Competitive Comparison — measured, side by side"), BODY_FONT, 11.5, INK, bold=True)
rp = R.paragraphs[0]; no_space(rp, after=0); rp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
set_font(rp.add_run("ESDS"), BODY_FONT, 12.5, ACCENT, bold=True)
for line in ("Research and Development", "Ayush Sinha", "",
             "Version 1.0  ·  8 September 2026",
             "Confidential — customer and executive distribution"):
    z = R.add_paragraph(); no_space(z, after=0, line=1.14)
    z.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    set_font(z.add_run(line), BODY_FONT, 7.0, MUTED)
hrule(P(after=5), "0A6A5C", 10)

RICH([("All three products were measured by ESDS in one continuous session on the same "
       "hardware, in front of the same origin server, against the same industry attack "
       "corpus, with no processor or memory limit applied to any of them. Where a "
       "competitor offers more than one sensitivity setting, both are shown: ", False),
      ("shipped default first, maximum second", True),
      (". Figures in green are the best of the three; figures in red are failures.", False)],
     size=8.8, after=6)

# ============================================== 1. PRODUCT AND APPROACH ===
H("1   Product and approach", before=2)
matrix([
 ["Detection engine", "OWASP Core Rule Set 4.7.0 signatures with a machine-learning "
  "classifier", "Semantic analysis; no signature corpus", "ModSecurity 3.0.14 with "
  "Core Rule Set 4.24.1"],
 ["Settings tested", "Shipped profile: paranoia 2, threshold 10, classifier on",
  "Shipped modules, then every module at strict", "Paranoia level 1 (shipped), then level 4"],
 ["Deployment", "One native process", "Seven containers; proxy and detection separate",
  "One container bundling the stack"],
 ["Licence of build tested", "Commercial", "Community edition", "Open source"],
], font=7.4)

# ================================================ 2. SECURITY EFFECTIVENESS
H("2   Security effectiveness")
matrix([
 ["Composite score", "99.64%", "58.28%  /  75.30%", "59.47%  /  68.51%"],
 ["Attack payloads blocked", "99.24%", "47.38%  /  60.47%", "47.09%  /  74.01%"],
 ["API attacks blocked", "100%", "42.86%  /  71.43%", "50.00%  /  100%"],
 ["Legitimate traffic allowed", "99.29%", "100.00%  /  97.87%", "90.78%  /  0.00%"],
 ["Legitimate requests wrongly blocked", "1 of 141", "0 of 141  /  3 of 141",
  "13 of 141  /  141 of 141"],
 ["Attack classes at zero detection", "none", "five classes, 86 payloads",
  "none at either setting"],
 ["Weakest class", "87.5%  (local file inclusion)", "0%  (five classes)",
  "0%  (four classes at PL1)"],
 ["Has a usable maximum setting", "single profile, no trade to make", "yes",
  "no — level 4 blocks all legitimate traffic"],
], font=7.4,
 winners={(0,1):ACCENT,(1,1):ACCENT,(2,1):ACCENT,(3,2):ACCENT,(4,2):ACCENT,
          (5,1):ACCENT,(3,3):BAD,(4,3):BAD,(5,2):BAD,(6,2):BAD,(6,3):BAD,(7,3):BAD},
 note="Read the two legitimate-traffic rows together with the two attack rows. BunkerWeb at "
      "level 4 blocks 74.01% of attacks and also every one of the 141 legitimate requests, so "
      "that setting cannot be deployed. SafeLine's five uncovered classes are LDAP injection, "
      "mail header injection, XML injection, CRLF injection and server-side includes; its "
      "engine has no module for them at any setting.")

# ==================================================== 3. WHERE EACH WINS ==
H("3   Where each product wins")
matrix([
 ["Best at", "Attack coverage: every class detected, none below 87.5%. Stability "
  "under attack load. Memory footprint.",
  "Precision: zero false positives at shipped settings. Deep SQL injection: 48 of "
  "48, including the one payload Swaraj Kavach misses. Lowest processor cost on "
  "legitimate traffic.",
  "No dimension in this evaluation."],
 ["Structural weakness", "Precision on traffic shapes its own benign corpus does not "
  "test — see section 6.",
  "Five attack classes with no module. Not reachable by configuration.",
  "No sensitivity setting that is both protective and deployable. Block path fails "
  "under attack load."],
], font=7.4, align=["l", "l", "l", "l"])

doc.add_page_break()

# ============================================================ 4. PERFORMANCE
H("4   Performance", before=0)
matrix([
 ["Legitimate throughput sustained", "7,595 /s", "6,006 /s  /  4,688 /s", "2,000 /s"],
 ["Latency, 99th percentile", "16.3 ms", "14.6 ms  /  22.9 ms", "94.4 ms"],
 ["Attack block rate sustained", "7,870 /s", "4,573 /s  /  4,054 /s",
  "376 /s   (1,541 /s reduced)"],
 ["Refusal response size", "125 B", "15,604 B — cannot be reduced (licensed feature)",
  "69,283 B — reducible to 146 B"],
 ["At 1,000 attacks/s, 99th pct", "1.63 ms", "1.97 ms  /  1.33 ms", "30 s — no response"],
 ["At 3,000 attacks/s, 99th pct", "8.16 ms", "59.1 ms  /  14.1 ms", "30 s — no response"],
 ["Requests lost at 3,000 attacks/s", "none of 45,000", "none of 45,000",
  "13,073 of 45,000   (4,672 reduced)"],
], font=7.4,
 winners={(0,1):ACCENT,(1,2):ACCENT,(2,1):ACCENT,(3,1):ACCENT,(4,2):ACCENT,
          (5,1):ACCENT,(6,1):ACCENT,(6,2):ACCENT,
          (2,3):BAD,(4,3):BAD,(5,3):BAD,(6,3):BAD},
 note="Refusal response size belongs next to the block-rate row: the three products differ by a "
      "factor of 554 and that, not the inspection engine, dominates maximum block rate. The "
      "fixed-rate rows isolate the engines. At 1,000 attacks per second the three are "
      "indistinguishable and SafeLine at strict is marginally the fastest; only at 3,000 does "
      "Swaraj Kavach separate. The bare origin with no firewall at all sustained 32,190 /s.")

# ====================================================== 5. COST TO OPERATE
H("5   Cost to operate")
matrix([
 ["Processor time per legitimate request", "636 µs",
  "419 µs inspection path  /  559 µs whole product", "2,918 µs"],
 ["Processor time per refused request", "648 µs",
  "724 µs inspection path  /  989 µs whole product", "41,518 µs"],
 ["Change in cost when blocking starts", "+2%", "+73%", "fourteenfold"],
 ["Peak memory under load", "131 MiB", "349 MiB path  /  1,381 MiB whole product", "993 MiB"],
 ["Memory at rest", "131 MiB", "568 MiB path  /  1,132 MiB whole product", "490 MiB"],
 ["Processor cores occupied under attack", "0.65 of 16", "0.70 of 16", "12.70 of 16"],
], font=7.4,
 winners={(0,2):ACCENT,(1,1):ACCENT,(2,1):ACCENT,(3,1):ACCENT,(4,1):ACCENT,(5,1):ACCENT,
          (0,3):BAD,(1,3):BAD,(2,3):BAD,(5,3):BAD},
 note="Identical load of 1,000 requests per second for 20 seconds against each product. "
      "Container processor time is read from the operating system control group and covers every "
      "process inside; Swaraj Kavach is one native process read from the kernel's own counters. "
      "Time is divided by requests actually answered. Memory partly reflects deployment shape, "
      "which is why both an inspection-path and a whole-product figure are given for SafeLine.")

# =================================================== 6. DISCLOSED OPENLY ==
H("6   Disclosed openly")
RICH([("One open defect in Swaraj Kavach. ", True),
      ("A legitimate login form carrying a persistent-session field is currently refused "
       "by the machine-learning classifier, which scores it above the blocking threshold "
       "on its own with no signature match. Two of eight ordinary form submissions tested "
       "are affected, both login forms; search, address, review and payment forms all "
       "pass. Remediation is a training-data change scheduled after the current stability "
       "measurement. Affected paths can run in monitoring mode per site meanwhile.", False)],
     size=8.4, after=3)
RICH([("A qualification on our own precision figure. ", True),
      ("The 141 legitimate requests in the industry corpus are plain text bodies, not "
       "form-encoded credential submissions, so the corpus cannot detect the defect above. "
       "The 99.29% in section 2 is accurate about the corpus and optimistic about "
       "production traffic.", False)], size=8.4, after=3)
RICH([("Measurement scope. ", True),
      ("One 16-thread host, loopback networking, no transport encryption. A reliable "
       "comparison between products under identical conditions, not a prediction of "
       "absolute throughput on customer hardware. API percentages rest on different "
       "denominators per product and are indicative only. Ten to fifteen large-payload "
       "requests could not be completed against SafeLine and were dropped from its "
       "denominator by the test tool rather than counted against it, which slightly "
       "favours SafeLine. No result here measures false-positive behaviour against real "
       "production traffic; that remains open work.", False)], size=8.4, after=5)

hrule(P(after=3), "C9D2CF", 4)
RICH([("Swaraj Kavach build 92e0d46, internal engineering codename sentinel. "
       "Detection by GoTestWAF, 675 attack and 141 legitimate payloads, HTTP 403 counted "
       "as blocked. Load by vegeta, 15-second runs, 200 concurrent connections. "
       "The full 24-page report carries per-class detection tables, all 22 load arms and "
       "the complete reproduction procedure.", False)], size=7.0, after=0)

out = os.path.join(HERE, "Swaraj-Kavach-Competitive-Comparison-v1.0.docx")
doc.save(out); print("saved:", out)
