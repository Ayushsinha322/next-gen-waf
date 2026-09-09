# -*- coding: utf-8 -*-
"""Build the enterprise benchmark report as a .docx."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Pt, Cm, RGBColor
from build_helpers import *
import content as C

HERE = os.path.dirname(os.path.abspath(__file__))
FIG = lambda n: os.path.join(HERE, "figs", n)
M = C.META

doc = Document()

# ---------------------------------------------------------------- base style
st = doc.styles["Normal"]
st.font.name = BODY_FONT; st.font.size = Pt(10.5); st.font.color.rgb = INK2
st.paragraph_format.space_after = Pt(7)
st.paragraph_format.line_spacing = 1.28
rf = st.element.rPr.rFonts
for a in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"): rf.set(qn(a), BODY_FONT)

sec = doc.sections[0]
for s in doc.sections:
    s.page_width, s.page_height = Cm(21.0), Cm(29.7)
    s.top_margin, s.bottom_margin = Cm(2.4), Cm(2.2)
    s.left_margin, s.right_margin = Cm(2.5), Cm(2.5)
    s.header_distance, s.footer_distance = Cm(1.2), Cm(1.1)

def P(text="", size=10.5, color=INK2, bold=False, italic=False, before=0, after=7,
      align=None, font=BODY_FONT, line=1.28):
    p = doc.add_paragraph(); no_space(p, before, after, line)
    if align: p.alignment = align
    if text: set_font(p.add_run(text), font, size, color, bold, italic)
    return p

def RICH(parts, size=10.5, before=0, after=7, line=1.28):
    """parts: list of (text, bold) or (text, bold, color)."""
    p = doc.add_paragraph(); no_space(p, before, after, line)
    for t in parts:
        txt, bold = t[0], t[1]
        col = t[2] if len(t) > 2 else INK2
        set_font(p.add_run(txt), BODY_FONT, size, col, bold)
    return p

def H1(num, text):
    doc.add_paragraph().paragraph_format.space_after = Pt(2)
    p = doc.add_paragraph(); no_space(p, before=14, after=2); keep_with_next(p)
    set_font(p.add_run(num + "  "), MONO_FONT, 11, ACCENT, bold=True)
    set_font(p.add_run(text), BODY_FONT, 17, INK, bold=True)
    hrule(p, "C9D2CF", 6)
    doc.add_paragraph().paragraph_format.space_after = Pt(3)

def H2(text):
    p = doc.add_paragraph(); no_space(p, before=13, after=3); keep_with_next(p)
    set_font(p.add_run(text), BODY_FONT, 12, ACCENT, bold=True)

def H3(text):
    p = doc.add_paragraph(); no_space(p, before=10, after=2); keep_with_next(p)
    set_font(p.add_run(text), BODY_FONT, 10.5, INK, bold=True)

def BULLETS(items, size=10.5):
    for it in items:
        p = doc.add_paragraph(style="List Bullet"); no_space(p, before=1, after=4, line=1.25)
        p.paragraph_format.left_indent = Cm(0.7)
        if isinstance(it, list):
            for t in it:
                col = t[2] if len(t) > 2 else INK2
                set_font(p.add_run(t[0]), BODY_FONT, size, col, t[1])
        else:
            set_font(p.add_run(it), BODY_FONT, size, INK2)

def PAGEBREAK():
    doc.add_page_break()

# =========================================================== COVER PAGE ====
doc.add_paragraph().paragraph_format.space_after = Pt(30)
p = P(align=WD_ALIGN_PARAGRAPH.LEFT, after=0)
set_font(p.add_run(M["org"]), BODY_FONT, 26, ACCENT, bold=True)
p = P(after=1)
set_font(p.add_run(M["unit"]), BODY_FONT, 9.5, MUTED)
p = P(after=2)
set_font(p.add_run(M["author"]), BODY_FONT, 9.5, INK2)
hrule(P(after=0), "0A6A5C", 12)
doc.add_paragraph().paragraph_format.space_after = Pt(26)

p = P(after=1, line=1.0)
set_font(p.add_run(M["product"]), BODY_FONT, 30, ACCENT, bold=True)
p = P(after=14)
set_font(p.add_run(M["descriptor"]), BODY_FONT, 11.5, INK2)
p = P(after=6, line=1.08)
set_font(p.add_run(M["title"]), BODY_FONT, 25, INK, bold=True)
p = P(after=0, line=1.3)
set_font(p.add_run(M["subtitle"]), BODY_FONT, 12, MUTED)

doc.add_paragraph().paragraph_format.space_after = Pt(28)
t = table(doc, ["", ""], [
    ["Document version", M["version"]],
    ["Date of issue", M["date"]],
    ["Product under test", f'{M["product"]} — {M["descriptor"]}'],
    ["Build identifier", f'{M["build"]} (internal codename {M["codename"]})'],
    ["Comparison products", "BunkerWeb 1.6.9 (all-in-one)\nSafeLine 9.4.1 Community"],
    ["Measurement basis", "All results captured in a single test session on identical hardware"],
    ["Classification", M["classif"]],
], widths=[5.6, 10.0], align=["l", "l"], font=9.5, mono=False)
# strip the empty header row on the cover table
t._tbl.remove(t.rows[0]._tr)

doc.add_paragraph().paragraph_format.space_after = Pt(16)
callout(doc, "Statement of method",
  [[("Every figure was measured by ", False), ("ESDS", True),
    (" on its own hardware, in one continuous session, with all three products "
     "sharing a single origin server, attack corpus and load generator.", False)],
   [("No figure is quoted from a vendor datasheet and no result has been excluded. "
     "Section 9 discloses where competing products outperform ours, together with "
     "one open defect in our own product.", False)]])

# ============================================ SECTION BREAK: BODY ==========
new = doc.add_section(WD_SECTION.NEW_PAGE)
new.page_width, new.page_height = Cm(21.0), Cm(29.7)
new.top_margin, new.bottom_margin = Cm(2.4), Cm(2.2)
new.left_margin, new.right_margin = Cm(2.5), Cm(2.5)
new.header_distance, new.footer_distance = Cm(1.2), Cm(1.1)

# cover section: no header/footer
doc.sections[0].header.is_linked_to_previous = False
doc.sections[0].footer.is_linked_to_previous = False
for par in doc.sections[0].header.paragraphs + doc.sections[0].footer.paragraphs:
    par.text = ""

sp = new._sectPr
pgnum = OxmlElement("w:pgNumType"); pgnum.set(qn("w:start"), "1"); sp.append(pgnum)

hd = new.header; hd.is_linked_to_previous = False
hp = hd.paragraphs[0]; no_space(hp, after=0)
hp.alignment = WD_ALIGN_PARAGRAPH.LEFT
set_font(hp.add_run(f'{M["product"]}  ·  {M["title"]}'), BODY_FONT, 8, MUTED)
hp.add_run("\t")
set_font(hp.add_run(M["classif"].split("—")[0].strip()), BODY_FONT, 8, MUTED)
hrule(hp, "DDE4E1", 4)

ft = new.footer; ft.is_linked_to_previous = False
fp = ft.paragraphs[0]; no_space(fp, before=0, after=0)
set_font(fp.add_run(f'{M["org"]}  ·  Version {M["version"]}  ·  {M["date"]}'),
         BODY_FONT, 8, MUTED)
fp.add_run("\t")
set_font(fp.add_run("Page "), BODY_FONT, 8, MUTED)
set_font(field(fp, "PAGE"), BODY_FONT, 8, MUTED, bold=True)
for para in (hp, fp):
    tabs = para.paragraph_format.tab_stops
    tabs.add_tab_stop(Cm(16.0), 2)   # right-aligned tab at the text edge

# --------------------------------------------------- document control ------
H1("", "Document control")
table(doc, ["Field", "Detail"], C.DOC_CONTROL,
      widths=[5.2, 10.4], align=["l", "l"], font=9.5, mono=False)

H2("Contents")
for num, title in C.CONTENTS:
    p = doc.add_paragraph(); no_space(p, before=1, after=2, line=1.2)
    set_font(p.add_run(f"{num}".ljust(4)), MONO_FONT, 9, ACCENT, bold=True)
    set_font(p.add_run("   " + title), BODY_FONT, 10, INK2)

PAGEBREAK()

# ================================================ 1. EXECUTIVE SUMMARY ====
H1("1", "Executive summary")

RICH([("ESDS has completed a controlled, measured comparison of ", False),
      ("Swaraj Kavach", True),
      (", its next-generation web application firewall, against the two most widely "
       "deployed free web application firewalls, "
       "BunkerWeb 1.6.9 and SafeLine 9.4.1. All three products were tested in one "
       "continuous session on the same hardware, in front of the same origin server, "
       "using the same industry-standard attack corpus and the same load generator.", False)],
     size=11.5)

RICH([("Swaraj Kavach blocked ", False), ("99.2 per cent", True),
      (" of 675 attack payloads while allowing ", False), ("99.3 per cent", True),
      (" of legitimate traffic through. The strongest configuration either competitor "
       "could reach was 74.0 per cent attack detection, and in that configuration "
       "BunkerWeb blocked every single legitimate request, making the setting unusable "
       "in production. On sustained legitimate traffic Swaraj Kavach handled "
       "7,595 requests per second against SafeLine's 6,006 and BunkerWeb's 2,000, in "
       "131 MiB of memory against 993 MiB and 1,381 MiB respectively.", False)])

table(doc, C.DETECT_HEAD["headers"], C.DETECT_HEAD["rows"],
      widths=[5.8, 2.0, 1.9, 2.0, 2.0, 1.9], font=8.5, ours_rows=(0,),
      caption="Table 1 — Security effectiveness, all five configurations",
      col_colors={(4, 4): ACCENT, (4, 5): BAD, (1, 4): ACCENT, (1, 5): ACCENT,
                  (0, 1): ACCENT, (0, 2): ACCENT})

H2("Principal findings")
BULLETS([
  [("Detection breadth is decisive and structural. ", True),
   ("Swaraj Kavach covers every attack class in the corpus. SafeLine records "
    "zero detection across five complete classes — LDAP injection, mail header "
    "injection, XML injection, CRLF injection and server-side includes, 86 payloads "
    "in total — at every available setting, because its engine contains no module for "
    "them. This is absent capability rather than conservative tuning, and no "
    "configuration change reaches it.", False)],
  [("Competing products cannot be tuned into competitiveness. ", True),
   ("BunkerWeb offers broad coverage that is either too permissive to stop half of the "
    "corpus or, at maximum sensitivity, so aggressive that it rejects all legitimate "
    "traffic. No usable setting exists between those two states.", False)],
  [("Cost per request does not change when the product starts blocking. ", True),
   ("Swaraj Kavach consumes 636 microseconds of processor time to allow a "
    "request and 648 to refuse one, with memory unchanged at 131 MiB. SafeLine's "
    "processor cost rises by 73 per cent under attack and BunkerWeb's by a factor of "
    "fourteen. Predictable cost under attack is what makes capacity planning possible.", False)],
  [("Only Swaraj Kavach absorbed every attack flood without loss. ", True),
   ("At 3,000 attacks per second it refused all 45,000 requests with a 99th-percentile "
    "latency of 8.16 milliseconds. BunkerWeb failed to answer 13,073 of them, and "
    "still lost 4,672 after its refusal page was reduced in size.", False)],
  [("Two areas require candid disclosure. ", True),
   ("SafeLine is materially more precise than our product on legitimate traffic, "
    "rejecting none of the 141 benign requests against our one, and it is "
    "approximately one third less expensive in processor time per legitimate request. "
    "Separately, our own machine-learning classifier currently rejects a specific "
    "class of legitimate login form. Both are set out in section 9.", False)],
])

callout(doc, "For executive readers",
 [[("The competitive question this report answers is not whether Swaraj Kavach "
    "is faster. It is whether a commercial product can justify itself against "
    "capable free alternatives. ", False)],
  [("It can, on one specific and defensible basis: ", False),
   ("the free products each protect a subset of the attack surface and cannot be "
    "configured to protect the rest", True),
   (". SafeLine is precise but narrow. BunkerWeb is broad but cannot be set to a "
    "usable sensitivity. Swaraj Kavach is the only product tested that is "
    "simultaneously broad, precise enough for production, and stable under attack "
    "load.", False)]])


# =================================================== 2. PURPOSE / SCOPE ===
H1("2", "Purpose, scope and audience")

H2("Purpose")
P("This document records the results of a comparative technical evaluation of "
  "Swaraj Kavach against two established open-source web application firewalls. "
  "It is intended to support three decisions: whether the product's protective "
  "coverage is competitive, whether its performance is adequate for production "
  "deployment, and where engineering investment should next be directed.")

H2("Audience")
BULLETS([
  [("Prospective and existing customers ", True),
   ("evaluating Swaraj Kavach against alternatives, including free "
    "alternatives their own engineering teams may already be running.", False)],
  [("Executive and commercial stakeholders ", True),
   ("who require an evidence base for competitive claims. Every claim in this "
    "document is traceable to a measurement recorded in appendix A.", False)],
  [("Technical evaluators ", True),
   ("who wish to reproduce the results. Appendix B contains the complete procedure, "
    "including the configuration of the competing products.", False)],
])

H2("Scope")
P("The evaluation covers security effectiveness against a standard attack corpus, "
  "throughput and latency under legitimate and attack traffic, behaviour under "
  "sustained attack, and processor and memory consumption. It does not cover "
  "management interfaces, clustering, reporting, integration surfaces, commercial "
  "terms or support arrangements.")

H2("Limitations of scope")
P("This is a laboratory measurement on a single host. It is a reliable comparison "
  "between products under identical conditions and it is not a prediction of "
  "absolute performance on customer hardware. Section 9.3 states the limitations in "
  "full. In particular, no result in this document constitutes a measurement of "
  "false-positive behaviour against real production traffic, which is a separate "
  "programme of work.")

# ================================================= 3. PRODUCTS EVALUATED ==
H1("3", "Products evaluated")

table(doc, ["", "Swaraj Kavach", "BunkerWeb 1.6.9", "SafeLine 9.4.1"], [
  ["Detection approach", "Signature engine on OWASP Core Rule Set 4.7.0, with a "
   "machine-learning classifier", "Signature engine: ModSecurity 3.0.14 with Core "
   "Rule Set 4.24.1", "Semantic analysis engine; no signature corpus"],
  ["Deployment shape", "Single native process", "Single container bundling the full stack",
   "Seven containers; proxy and detection are separate services"],
  ["Configuration tested", "Shipped detection profile: paranoia level 2, anomaly "
   "threshold 10, classifier enabled", "Shipped defaults (paranoia level 1) and "
   "maximum sensitivity (paranoia level 4)", "Shipped module set, and every semantic "
   "module raised to strict"],
  ["Licence of tested build", "Commercial", "Open source", "Community edition"],
], widths=[3.3, 4.3, 4.0, 4.0], align=["l","l","l","l"], font=8.5, mono=False,
  caption="Table 2 — Products and configurations under test",
  note="Swaraj Kavach was measured in one configuration, its shipped detection "
       "profile. Both competing products were measured at shipped defaults and again at "
       "their maximum available detection setting, so that neither is represented only by "
       "its weakest configuration.")

RICH([("Selecting the comparison products. ", True),
      ("BunkerWeb and SafeLine were selected because they are the two free products "
       "most frequently encountered in competitive evaluations, and because they "
       "represent opposite architectural philosophies. BunkerWeb is signature-driven, "
       "which makes it the closest technical comparison to our own engine. SafeLine "
       "relies on semantic analysis with no signature corpus at all, which tests our "
       "detection against a fundamentally different method rather than against another "
       "implementation of the same one.", False)])


# ==================================================== 4. METHODOLOGY ======
H1("4", "Test methodology")

H2("4.1  Test environment")
table(doc, ["Component", "Detail"], [
  ["Host", "AMD Ryzen 7 7730U, 16 hardware threads, 14 GiB memory"],
  ["Operating system", "Linux, container runtime Docker 26.1.5"],
  ["Origin server", "One shared container returning HTTP 200 to every method and path"],
  ["Network path", "Loopback interface for all three products; no transport encryption"],
  ["Attack corpus", "GoTestWAF: 675 attack payloads across 25 classes, plus 141 legitimate requests"],
  ["Load generator", "vegeta: 15-second runs, persistent connections, 200 concurrent connections"],
  ["Decision criteria", "HTTP 403 counted as blocked; HTTP 200 and 404 counted as allowed"],
], widths=[4.4, 11.2], align=["l","l"], font=9, mono=False,
  caption="Table 3 — Test environment")

H2("4.2  Fairness controls")
P("Three specific measures were taken to prevent the harness itself from producing a "
  "misleading result. Each addresses a documented way in which web application "
  "firewall comparisons are commonly distorted.")

H3("Identical processor and memory allocation")
P("No processor quota, processor share weighting, processor affinity restriction or "
  "memory limit was applied to any product. All three had the whole machine "
  "available, and this was verified by inspecting the running container "
  "configurations and the operating system's own record of the process, rather than "
  "assumed from the absence of a configuration setting.")

H3("An origin server that cannot bias the result")
P("A conventional static web server returns HTTP 405 to legitimate requests that use "
  "methods it does not support. Because that status is neither a block nor an allow, "
  "it simultaneously inflates the measured attack detection rate and depresses the "
  "measured legitimate-traffic rate. The shared origin used here returns HTTP 200 to "
  "every method and every path, so the decision on each request is made solely by "
  "the product under test.")

H3("No product was permitted to ban the test source")
P("The attack corpus originates from a single network address. A product that blocks "
  "that address part-way through a run will thereafter appear to block every attack "
  "and also every legitimate request, producing a result that is meaningless in both "
  "directions. Address-banning and rate-limiting features were disabled in all three "
  "products, and a legitimate request was issued immediately after every individual "
  "run to confirm no ban was in force. All such checks returned HTTP 200.")

callout(doc, "A trap specific to BunkerWeb", [
  [("BunkerWeb proxies traffic without its rule engine engaged for approximately the "
    "first fifteen seconds after start. A detection run begun during that window "
    "produces an invalid result. Every BunkerWeb measurement in this report waited "
    "until a live attack probe was confirmed to be refused before beginning, which "
    "took 20 seconds at default sensitivity and 15 at maximum.", False)]], accent=False)

H2("4.3  What was measured")
BULLETS([
  [("Security effectiveness. ", True),
   ("Proportion of 675 attack payloads refused, and proportion of 141 legitimate "
    "requests allowed. Both are reported for every configuration; neither is "
    "meaningful without the other.", False)],
  [("Throughput and latency. ", True),
   ("Maximum sustained request rate under legitimate traffic and under attack "
    "traffic, with median, 99th and 99.9th percentile response times.", False)],
  [("Behaviour under sustained attack. ", True),
   ("Response times and request losses at fixed rates of 1,000 and 3,000 attacks per "
    "second, which distinguishes a product that slows down from one that fails.", False)],
  [("Resource efficiency. ", True),
   ("Processor time and peak memory consumed while handling an identical load, "
    "normalised per request actually answered.", False)],
])

PAGEBREAK()

# ================================== 5. SECURITY EFFECTIVENESS RESULTS =====
H1("5", "Security effectiveness results")

H2("5.1  Headline result")
P("Swaraj Kavach refused 670 of 675 attack payloads and allowed 140 of 141 "
  "legitimate requests. No competing configuration achieved both a higher attack "
  "detection rate and an acceptable legitimate-traffic rate.")

figure(doc, FIG("fig1-detection.png"),
       "Figure 1 — Attack payloads refused (solid) against legitimate requests allowed "
       "(shaded), by product and configuration. Both measures must be read together: "
       "BunkerWeb at maximum sensitivity refuses 74.0 per cent of attacks and also "
       "100 per cent of legitimate traffic.")

H2("5.2  Detection by attack class")
P("A single composite score conceals the most commercially important fact in this "
  "evaluation, which is that the two competing products fail on entirely different "
  "parts of the attack surface.")

rows, groups = [], []
for row in C.CLASSES:
    if row[0] == "GROUP":
        groups.append(len(rows)); rows.append([row[1], "", "", "", "", ""])
    else:
        rows.append(list(row))
cc = {}
for i, r in enumerate(rows):
    if i in groups: continue
    for j in range(1, 6):
        if r[j] in ("0",):  cc[(i, j)] = BAD
        elif r[j] in ("100", "15/15") and j == 1: cc[(i, j)] = ACCENT
table(doc, ["Attack class (payloads sent)", "ESDS\nWAF", "BunkerWeb\nPL1",
            "BunkerWeb\nPL4", "SafeLine\ndefault", "SafeLine\nstrict"],
      rows, widths=[6.6, 1.8, 1.8, 1.8, 1.8, 1.8], font=8,
      group_rows=tuple(groups), col_colors=cc,
      caption="Table 4 — Percentage of payloads refused, by attack class",
      note="Figures are the percentage of payloads in each class that were refused. "
           "Values shown in red are complete detection failures. The final row reports "
           "large-payload cases as blocked over completed, because a small number of "
           "these requests could not be completed against SafeLine and were excluded "
           "from its denominator by the test tool rather than counted against it.")

H2("5.3  Interpretation")
RICH([("SafeLine is precise but structurally narrow. ", True),
      ("It is the only product tested that refused all 48 OWASP SQL-injection "
       "payloads, including the one payload our product does not detect, and the only "
       "one that allowed all 141 legitimate requests. Against that, it records zero "
       "detection across five complete attack classes at both of its settings. Those "
       "86 payloads are not a tuning gap; the engine has no module for them, and a "
       "customer running SafeLine cannot close that gap by configuration.", False)])

RICH([("BunkerWeb is broad but has no usable operating point. ", True),
      ("At shipped defaults it refuses 47.1 per cent of attacks while already "
       "rejecting 13 of 141 legitimate requests. Raised to maximum sensitivity it "
       "refuses 74.0 per cent of attacks and rejects every legitimate request in the "
       "corpus. Between those two configurations there is no setting that is both "
       "protective and deployable.", False)])

RICH([("Swaraj Kavach is the only product tested that is both broad and "
       "deployable. ", True),
      ("It records complete detection in 19 of the 25 classes and no class below 87.5 "
       "per cent, while allowing 99.3 per cent of legitimate traffic. Its two weakest "
       "classes, local file inclusion at 87.5 per cent and scanner detection at 88.9 "
       "per cent, are classes in which both SafeLine configurations are far behind.", False)])


# ======================================== 6. PERFORMANCE RESULTS ==========
H1("6", "Performance results")

H2("6.1  Legitimate traffic")
P("Maximum sustained throughput was measured with an open-loop generator and 64 "
  "workers, so that each product was driven to its own limit rather than to a fixed "
  "rate. Every arm completed with no failed requests.")

table(doc, C.PERF_CLEAN["headers"], C.PERF_CLEAN["rows"],
      widths=[5.4, 2.3, 1.9, 2.4, 2.0, 1.6], font=8.5, ours_rows=(1,),
      caption="Table 5 — Throughput and latency, legitimate traffic")

figure(doc, FIG("fig2-throughput.png"),
       "Figure 2 — Maximum sustained throughput on legitimate traffic. The unprotected "
       "origin is shown as the ceiling against which every product is working.")

P("Swaraj Kavach sustains 26 per cent more legitimate traffic than SafeLine "
  "at its defaults, 62 per cent more than SafeLine at strict, and 3.8 times "
  "BunkerWeb. It should be stated plainly that SafeLine is a capable performer and "
  "the margin over it is modest.")

H2("6.2  Attack traffic")
P("Under attack traffic every request must be inspected and refused. This "
  "measurement is reported together with the size of each product's refusal "
  "response, because that size, rather than the inspection engine, dominates the "
  "result.")

table(doc, C.PERF_ATTACK["headers"], C.PERF_ATTACK["rows"],
      widths=[5.8, 2.7, 2.4, 2.2, 2.5], font=8.5, ours_rows=(0,),
      caption="Table 6 — Block rate and latency, attack traffic",
      note=C.PERF_ATTACK["note"])

H2("6.3  Behaviour under sustained attack")
P("The preceding measurement establishes each product's ceiling. The more important "
  "operational question is what happens when attack traffic arrives at a fixed rate "
  "the product must absorb. This distinguishes a product that becomes slower from "
  "one that stops answering.")

table(doc, C.PERF_FIXED["headers"], C.PERF_FIXED["rows"],
      widths=[4.9, 1.8, 1.8, 1.5, 1.8, 1.8, 1.6], font=8, ours_rows=(0,),
      caption="Table 7 — Fixed-rate attack traffic, 1,000 and 3,000 requests per second",
      note=C.PERF_FIXED["note"],
      col_colors={(3,1):BAD,(3,2):BAD,(3,3):BAD,(3,4):BAD,(3,5):BAD,(3,6):BAD,
                  (4,4):BAD,(4,5):BAD,(4,6):BAD})

figure(doc, FIG("fig4-attack.png"),
       "Figure 3 — Requests that received no response at all, of 45,000 attacks sent at "
       "3,000 per second. Only BunkerWeb lost traffic, and it lost traffic in both of "
       "its configurations.")

callout(doc, "The finding that matters operationally", [
  [("At 1,000 attacks per second the three inspection engines are ", False),
   ("indistinguishable", True),
   (", and SafeLine at maximum sensitivity is marginally the fastest of the three. "
    "Any claim of a large inspection-cost advantage at ordinary attack rates would "
    "not survive measurement.", False)],
  [("Separation appears at 3,000 per second. Swaraj Kavach holds 8.16 "
    "milliseconds at the 99th percentile and loses nothing. SafeLine also holds, more "
    "slowly. BunkerWeb ceases to function in both configurations, and reducing its "
    "refusal page from 69,283 bytes to 146 bytes raises its block rate fourfold but "
    "does not save it: the inspection engine beneath is the limit.", False)]])


# ======================================== 7. RESOURCE EFFICIENCY ==========
H1("7", "Resource efficiency results")

P("Throughput describes what a product can do. Resource consumption describes what it "
  "costs to run, and therefore how much hardware a customer must provision. Load was "
  "held identical at 1,000 requests per second for 20 seconds against every target.")

table(doc, C.RES["headers"], C.RES["rows"],
      widths=[5.9, 2.0, 2.0, 2.0, 1.9, 2.2], font=8.5,
      group_rows=(0, 5), ours_rows=(1, 6),
      caption="Table 8 — Processor time and memory at an identical 1,000 requests per second",
      note=C.RES["note"],
      col_colors={(9,1):BAD,(9,2):BAD,(9,3):BAD,(9,5):BAD})

figure(doc, FIG("fig3-cpu.png"),
       "Figure 4 — Processor time consumed per request. Lower is less expensive to "
       "operate. SafeLine is the least expensive product on legitimate traffic; "
       "Swaraj Kavach is the least expensive on attack traffic.")

H2("7.1  SafeLine is less expensive than our product on legitimate traffic")
RICH([("This result goes against Swaraj Kavach and is reported without "
       "qualification. ", True),
      ("SafeLine handles a legitimate request for 419 microseconds of processor time "
       "against our 636, and its complete seven-container product still comes in below "
       "our single process at 559 microseconds. Under attack traffic the position "
       "reverses: our product refuses a request for 648 microseconds against SafeLine's "
       "724, or 989 counting its full deployment.", False)])

H2("7.2  The cost is the rule engine, not the classifier")
P("Because the machine-learning classifier is the obvious suspect for additional "
  "processor cost, this was tested rather than assumed. Two instances were run from an "
  "identical configuration at an identical logging level, differing only in whether "
  "the classifier was enabled.")

table(doc, ["Configuration", "Processor time per legitimate request"], [
  ["Classifier enabled (shipped profile)", "0.666 ms"],
  ["Classifier disabled (signatures only)", "0.717 ms"],
], widths=[8.0, 7.6], align=["l","r"], font=9,
  caption="Table 9 — Attribution of processor cost",
  note="The classifier is not the source of the cost. It is marginally negative, because "
       "a confident classification allows rule evaluation to stop early. The cost is the "
       "evaluation of 350 compiled signatures against every request, which is the same "
       "mechanism that produces the coverage advantage in table 4.")

P("This is a genuine engineering trade rather than an inefficiency. The product spends "
  "approximately 200 microseconds more per legitimate request than SafeLine, and in "
  "return covers five attack classes on which SafeLine detects nothing at all.")

H2("7.3  Memory")
figure(doc, FIG("fig5-memory.png"),
       "Figure 5 — Peak resident memory under load. Both a inspection-path figure and a "
       "complete-product figure are given for SafeLine, because it distributes "
       "inspection across separate services.", width_cm=15.0)

table(doc, ["Product", "Memory at rest, before any load"], C.IDLE_MEM,
      widths=[8.6, 7.0], align=["l","r"], font=9,
      caption="Table 10 — Memory at rest")

RICH([("Swaraj Kavach occupies 131 MiB and does not move. ", True),
      ("Its memory figure is identical on legitimate and attack traffic, at rest and "
       "under load. SafeLine's inspection path occupies between 328 and 349 MiB and its "
       "complete product between 1,132 and 1,449 MiB. BunkerWeb occupies between 490 and "
       "1,110 MiB. One qualification is due: these products are packaged very "
       "differently, and the memory comparison therefore reflects deployment shape as "
       "well as inspection cost. That is why both a inspection-path and a "
       "complete-product figure are reported for SafeLine.", False)])


# ======================================= 8. COMPETITIVE POSITIONING =======
H1("8", "Competitive positioning")

table(doc, ["Dimension", "Swaraj Kavach", "SafeLine 9.4.1", "BunkerWeb 1.6.9"], [
  ["Attack coverage", "Complete across all 25 classes; lowest class 87.5%",
   "Five classes at zero, unreachable by configuration", "Complete coverage, but no usable sensitivity setting"],
  ["Precision on legitimate traffic", "99.3% allowed; one open defect (section 9.1)",
   "100% allowed at defaults — best of the three", "90.8% at defaults; 0% at maximum sensitivity"],
  ["Deep SQL injection", "47 of 48", "48 of 48 — best of the three", "19 of 48 at defaults"],
  ["Legitimate throughput", "7,595 per second — best of the three", "6,006 per second", "2,000 per second"],
  ["Cost per legitimate request", "636 microseconds", "419 microseconds — best of the three", "2,918 microseconds"],
  ["Cost per refused request", "648 microseconds — best of the three", "724 microseconds", "41,518 microseconds"],
  ["Stability under attack flood", "No loss at 3,000 per second", "No loss at 3,000 per second", "Loses 10–29% of traffic"],
  ["Memory footprint", "131 MiB, constant — best of the three", "349 MiB path; 1,381 MiB complete", "993 MiB"],
], widths=[3.5, 4.3, 4.0, 3.8], align=["l","l","l","l"], font=8.5, mono=False,
  caption="Table 11 — Position by dimension")

H2("Where each product should be expected to win")
BULLETS([
  [("Swaraj Kavach ", True),
   ("wins wherever the customer's exposure is broad — multiple application "
    "technologies, API surfaces, inherited or third-party code — and wherever attack "
    "load must be absorbed without degradation. It is the only product tested that "
    "does not require the customer to accept either a coverage gap or an unusable "
    "sensitivity setting.", False)],
  [("SafeLine ", True),
   ("wins where the customer's dominant concern is never blocking a legitimate user "
    "and the protected application's realistic threat is confined to SQL injection "
    "and cross-site scripting. Its precision at default settings is genuinely better "
    "than ours and should not be disputed in competitive discussions.", False)],
  [("BunkerWeb ", True),
   ("has no dimension in this evaluation on which it leads. Its coverage is broad in "
    "principle but unusable in practice at either sensitivity, and its behaviour "
    "under attack load is a material operational risk.", False)],
])

PAGEBREAK()

# ============================ 9. LIMITATIONS AND REMEDIATION ==============
H1("9", "Known limitations and remediation status")

P("This section exists so that no reader of this document is later surprised by "
  "something ESDS already knew. It records one open defect in our own product, the "
  "areas in which competing products outperform it, and the limitations of the "
  "measurement itself.")

H2("9.1  Open defect: legitimate login forms may be refused")
callout(doc, "Open — remediation scheduled", [
  [("A legitimate login form submission carrying a persistent-session field is "
    "currently refused by the machine-learning classifier.", True)],
  [("The classifier contributes an anomaly score of 13 against a blocking threshold "
    "of 10, which means the refusal occurs on the classifier's assessment alone, with "
    "no signature match involved. This was confirmed by comparing two instances built "
    "from an identical configuration and differing only in whether the classifier was "
    "enabled.", False)],
  [("Measured extent: of eight ordinary form submissions tested, two are refused, both "
    "of them login forms carrying a persistent-session field. Search forms, "
    "name and address forms, review submissions and payment forms were all allowed.", False)],
  [("Remediation is a matter of training-data coverage rather than threshold "
    "adjustment, and is scheduled to follow the current 46-hour stability measurement. "
    "Customers deploying in advance of that fix should run the affected paths in "
    "monitoring mode, which the product supports per site.", False)]], accent=False)

RICH([("A second and more important observation follows from that defect. ", True),
      ("The 141 legitimate requests in the industry corpus are plain text bodies, not "
       "form-encoded credential submissions. The corpus therefore cannot detect this "
       "class of error, which means the 99.29 per cent legitimate-traffic figure "
       "reported in table 1 is accurate with respect to the corpus and optimistic with "
       "respect to production traffic. ESDS states this rather than allowing the "
       "headline figure to stand unqualified.", False)])

H2("9.2  Areas in which competing products lead")
BULLETS([
  [("SafeLine is more precise. ", True),
   ("Zero of 141 legitimate requests refused at shipped defaults, against one for our "
    "product plus the defect above. Precision is SafeLine's stated design objective "
    "and it meets it.", False)],
  [("SafeLine detects one SQL-injection payload that we do not. ", True),
   ("48 of 48 against our 47 of 48, at both of its settings.", False)],
  [("SafeLine is approximately one third less expensive per legitimate request. ", True),
   ("419 microseconds against 636. Section 7.2 attributes the difference.", False)],
  [("BunkerWeb leads on local file inclusion. ", True),
   ("All 8 payloads in that class at both settings, against our 7 of 8. Our product "
    "leads the multipart variant of the same class, 2 of 2 against 0 of 2.", False)],
])

H2("9.3  Limitations of this measurement")
BULLETS([
  "A single 16-thread host, loopback networking and no transport encryption. This is "
  "a reliable comparison between products under identical conditions, not a "
  "prediction of absolute performance on customer hardware.",
  "The attack corpus contains 675 payloads across 25 classes. It is a reasonable "
  "breadth test and it is not a substitute for real traffic. Its legitimate-traffic "
  "half is particularly narrow, as section 9.1 demonstrates.",
  "API detection percentages rest on different denominators for each product and are "
  "indicative only.",
  "A small number of large-payload requests could not be completed against SafeLine "
  "and were excluded from its denominator by the test tool rather than counted "
  "against it, which slightly favours SafeLine. The behaviour did not reproduce when "
  "the same requests were replayed in isolation and under concurrency.",
  "Swaraj Kavach was measured in one configuration. Both competitors were "
  "measured at defaults and at maximum sensitivity. A signatures-only measurement of "
  "our engine from an earlier session placed it at 90.91 per cent composite, which "
  "separates engine from classifier, but that arm was not repeated in this session.",
  "Resource figures are single 20-second windows. They are sufficient to separate "
  "419 from 636 from 2,918 microseconds and insufficient to characterise long-run "
  "drift, which a separate 46-hour stability measurement addresses for our product only.",
  "No result in this document measures false-positive behaviour against real "
  "production traffic. That remains an open programme of work and no claim about it "
  "is made here.",
])


# ================================ 10. CONCLUSIONS =========================
H1("10", "Conclusions and recommendations")

H2("Conclusions")
RICH([("On protective coverage the advantage is substantial and durable. ", True),
      ("Swaraj Kavach refuses 99.2 per cent of a 675-payload corpus while "
       "allowing 99.3 per cent of legitimate traffic. The best result any competitor "
       "reached at a deployable setting was 60.5 per cent. The advantage does not "
       "narrow when competitors are given their strongest configuration, because their "
       "shortfalls are structural: SafeLine has no module for five attack classes and "
       "BunkerWeb has no sensitivity setting that is simultaneously protective and "
       "usable.", False)])

RICH([("On performance the position is strong but should be stated proportionately. ",
       True),
      ("Our product leads legitimate throughput by 26 per cent over SafeLine and by a "
       "factor of 3.8 over BunkerWeb, and is the only product to absorb every attack "
       "flood without loss. SafeLine is nonetheless a capable performer that consumes "
       "less processor time than we do on legitimate traffic, and competitive material "
       "should not characterise it as slow.", False)])

RICH([("On precision we are currently behind SafeLine and the reason is understood. ",
       True),
      ("One open classifier defect affects a specific class of legitimate login form, "
       "remediation is scheduled, and the industry corpus that produced our "
       "legitimate-traffic figure cannot detect that class of error.", False)])

H2("Recommendations")
BULLETS([
  [("Engineering. ", True),
   ("Extend the classifier's training corpus to cover form-encoded credential "
    "submissions and re-measure. This is the single action this evaluation generates, "
    "and it addresses both the defect in section 9.1 and the blind spot in our "
    "precision measurement.", False)],
  [("Engineering. ", True),
   ("Establish a false-positive measurement against mirrored production traffic. Until "
    "that exists, no precision claim rests on anything but a 141-payload corpus.", False)],
  [("Commercial. ", True),
   ("Position on coverage breadth and stability under load, which are measured and "
    "defensible. Do not position on raw speed against SafeLine, where the margin is "
    "modest and the processor-efficiency comparison runs against us.", False)],
  [("Commercial. ", True),
   ("Where a prospect is already running SafeLine, the productive question is which "
    "of the five uncovered attack classes are present in their application estate. "
    "Where a prospect is running BunkerWeb, the productive question is which "
    "sensitivity setting they are using and what it is costing them in either missed "
    "attacks or rejected customers.", False)],
])

PAGEBREAK()

# ================================ APPENDIX A ==============================
H1("A", "Appendix A — Complete result tables")

H2("A.1  Security effectiveness, raw counts")
table(doc, ["Configuration", "Attacks\noffered", "Attacks\nrefused", "Attacks\nallowed",
            "Not\ncompleted", "Legitimate\noffered", "Legitimate\nrefused"], [
  ["Swaraj Kavach", "675", "670", "5", "0", "141", "1"],
  ["SafeLine, shipped defaults", "675", "314", "350", "10", "141", "0"],
  ["SafeLine, all modules strict", "675", "400", "259", "15", "141", "3"],
  ["BunkerWeb, PL1", "675", "318", "357", "0", "141", "13"],
  ["BunkerWeb, PL4", "675", "500", "175", "0", "141", "141"],
], widths=[4.6, 1.8, 1.8, 1.8, 1.7, 2.0, 1.9], font=8.5, ours_rows=(0,),
  caption="Table A.1 — Attack and legitimate request counts",
  note="Requests that could not be completed are excluded from the denominator by the "
       "test tool, which slightly favours the affected product. Only SafeLine was "
       "affected.")

H2("A.2  Load-test arms as executed")
table(doc, ["Arm", "Traffic", "Rate applied", "Achieved", "Median",
            "99th pct", "Lost"], [
  ["Origin, no WAF", "legitimate", "unbounded", "32,190 /s", "1.74 ms", "4.79 ms", "0"],
  ["Swaraj Kavach", "legitimate", "unbounded", "7,595 /s", "7.45 ms", "16.3 ms", "0"],
  ["SafeLine, defaults", "legitimate", "unbounded", "6,006 /s", "10.7 ms", "14.6 ms", "0"],
  ["SafeLine, strict", "legitimate", "unbounded", "4,688 /s", "13.1 ms", "22.9 ms", "0"],
  ["BunkerWeb, PL1", "legitimate", "unbounded", "2,000 /s", "27.5 ms", "94.4 ms", "0"],
  ["Swaraj Kavach", "attack", "unbounded", "7,870 /s", "7.49 ms", "15.8 ms", "0"],
  ["SafeLine, defaults", "attack", "unbounded", "4,573 /s", "12.0 ms", "29.7 ms", "0"],
  ["SafeLine, strict", "attack", "unbounded", "4,054 /s", "13.1 ms", "37.4 ms", "0"],
  ["BunkerWeb, error page on", "attack", "unbounded", "376 /s", "135 ms", "722 ms", "0"],
  ["BunkerWeb, error page off", "attack", "unbounded", "1,541 /s", "38.0 ms", "103 ms", "0"],
  ["Swaraj Kavach", "attack", "1,000 /s", "1,000 /s", "0.65 ms", "1.63 ms", "0"],
  ["SafeLine, defaults", "attack", "1,000 /s", "1,000 /s", "0.81 ms", "1.97 ms", "0"],
  ["SafeLine, strict", "attack", "1,000 /s", "1,000 /s", "0.78 ms", "1.33 ms", "0"],
  ["BunkerWeb, error page on", "attack", "1,000 /s", "1,000 /s", "10.8 s", "30 s", "2,404"],
  ["BunkerWeb, error page off", "attack", "1,000 /s", "1,000 /s", "5.13 ms", "137 ms", "0"],
  ["Swaraj Kavach", "attack", "3,000 /s", "3,000 /s", "0.93 ms", "8.16 ms", "0"],
  ["SafeLine, defaults", "attack", "3,000 /s", "3,000 /s", "1.19 ms", "59.1 ms", "0"],
  ["SafeLine, strict", "attack", "3,000 /s", "3,000 /s", "1.34 ms", "14.1 ms", "0"],
  ["BunkerWeb, error page on", "attack", "3,000 /s", "1,282 /s", "13.4 s", "30 s", "13,073"],
  ["BunkerWeb, error page off", "attack", "3,000 /s", "2,299 /s", "2.79 s", "30 s", "4,672"],
], widths=[4.3, 1.9, 2.0, 1.9, 1.8, 1.8, 1.7], font=7.8,
  caption="Table A.2 — Every load-test arm, 15-second runs, 200 concurrent connections",
  note="'Unbounded' arms used an open loop with 64 workers to drive each product to its "
       "own limit. 'Achieved' below the applied rate indicates the product could not "
       "accept the offered load.")

PAGEBREAK()

# ================================ APPENDIX B ==============================
H1("B", "Appendix B — Reproduction procedure")

P("The procedure below reproduces every figure in this report. It is included so that "
  "a technical evaluator can verify the results independently, including the "
  "configuration applied to the competing products.")

def CODE(lines, caption=None):
    if caption:
        p = doc.add_paragraph(); no_space(p, before=8, after=3); keep_with_next(p)
        set_font(p.add_run(caption), MONO_FONT, 7.5, MUTED, bold=True)
    t = doc.add_table(rows=1, cols=1)
    c = t.cell(0, 0); shade(c, "F2F6F5")
    cell_borders(c, left="C9D2CF", size=12); cell_margins(c, 110, 110, 150, 120)
    first = c.paragraphs[0]
    for i, ln in enumerate(lines):
        par = first if i == 0 else c.add_paragraph()
        no_space(par, after=0, line=1.18)
        set_font(par.add_run(ln), MONO_FONT, 7.8, INK2)
    doc.add_paragraph().paragraph_format.space_after = Pt(6)

H2("B.1  Shared origin server")
CODE(["docker run -d --name bench-origin \\",
      "  -v $PWD/origin-all-methods.nginx.conf:/etc/nginx/conf.d/default.conf:ro \\",
      "  nginx:alpine",
      "",
      "# returns HTTP 200 to every method and path, so the WAF alone decides"])

H2("B.2  Swaraj Kavach")
CODE(["sed 's/host: \"127.0.0.1\", port: 18090/host: \"172.17.0.2\", port: 80/' \\",
      "  waf-detection.yaml > /tmp/det.yaml",
      "SENTINEL_DISABLE_CORRELATION=1 ./sentinel-bin --config /tmp/det.yaml &",
      "",
      "# repeat-offender correlation is disabled so a single-source corpus",
      "# is not escalated; this measures per-request inspection only"])

H2("B.3  BunkerWeb 1.6.9")
CODE(["docker run -d --name bw-bench -p 18093:8080 \\",
      "  -e SERVICE_UI=no -e SERVER_NAME=localhost \\",
      "  -e USE_REVERSE_PROXY=yes -e REVERSE_PROXY_HOST=http://172.17.0.2:80 \\",
      "  -e REVERSE_PROXY_URL=/ \\",
      "  -e USE_MODSECURITY=yes -e USE_MODSECURITY_CRS=yes -e SECURITY_MODE=block \\",
      "  -e USE_BAD_BEHAVIOR=no -e USE_LIMIT_REQ=no -e USE_LIMIT_CONN=no \\",
      "  -e USE_BLACKLIST=no -e USE_DNSBL=no -e USE_BUNKERNET=no \\",
      "  -e USE_WHITELIST=no -e USE_GREYLIST=no \\",
      "  bunkerity/bunkerweb-all-in-one:1.6.9",
      "",
      "# maximum sensitivity arm adds:",
      "#   -e 'CUSTOM_CONF_MODSEC_CRS_paranoia=SecAction \"id:900000,phase:1,pass,",
      "#        t:none,nolog,setvar:tx.blocking_paranoia_level=4\"'",
      "# small refusal page arm adds:",
      "#   -e 'INTERCEPTED_ERROR_CODES=400 401 404 405 413 429 500 501 502 503 504'",
      "",
      "# MANDATORY: wait until an attack probe is actually refused before testing.",
      "# BunkerWeb proxies without its rule engine for the first ~15 seconds.",
      "until [ \"$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: localhost' \\",
      "  'http://127.0.0.1:18093/?a=1%27+OR+%271%27=%271')\" = 403 ]; do sleep 5; done"])

H2("B.4  SafeLine 9.4.1")
P("SafeLine's console encrypts the password in the browser before submission, so its "
  "API cannot be driven with a plain credential. The scheme is recorded here because "
  "it is otherwise only discoverable by reading the console's compiled JavaScript.",
  size=9.5)
CODE(["# 1. obtain the symmetric key and a request token",
      "GET  /api/open/system/key   ->  {\"data\": \"<16-character key>\"}",
      "GET  /api/open/auth/csrf    ->  {\"data\": {\"csrf_token\": \"...\"}}",
      "",
      "# 2. submit the login with the password encrypted client-side",
      "POST /api/open/auth/login   {username, password, csrf_token}",
      "     password = base64( iv || AES-128-CBC/PKCS7(plaintext, key, iv) )",
      "     iv       = the hexadecimal rendering of 8 random bytes, used",
      "                directly as the 16-byte initialisation vector",
      "",
      "# 3. create the test site",
      "POST /api/open/site  {server_names:[\"*\"], ports:[\"18092\"],",
      "                      upstreams:[\"http://172.17.0.2:80\"],",
      "                      load_balance:{balance_type:1}, mode:0}",
      "",
      "# 4. maximum sensitivity arm",
      "PUT  /api/open/global/mode  {semantics:{<every module>:\"strict\"}}",
      "     valid values: disable | default | dryrun | strict",
      "     SafeLine ships two modules disabled: m_scanner and m_response"])

H2("B.5  Detection measurement")
CODE(["docker run --rm --network host -v $PWD/out:/app/reports \\",
      "  wallarm/gotestwaf:latest --url http://localhost:<PORT> \\",
      "  --blockStatusCodes 403 --passStatusCodes 200,404 \\",
      "  --workers 10 --randomDelay 20 --skipWAFIdentification \\",
      "  --noEmailReport --reportPath /app/reports",
      "",
      "# after EVERY run, confirm the source was not banned.",
      "# a refusal here invalidates the legitimate-traffic score.",
      "curl -s -o /dev/null -w '%{http_code}\\n' http://localhost:<PORT>/"])

H2("B.6  Load measurement")
CODE(["# stream straight into the report. a 15-second open-loop capture against",
      "# a 32,000-per-second origin writes gigabytes of intermediate data.",
      "vegeta attack -duration=15s -rate=0 -max-workers=64 -connections=200 \\",
      "  -targets=clean.txt | vegeta report -type=json",
      "",
      "# fixed-rate arms",
      "vegeta attack -duration=15s -rate=1000 -timeout=30s -connections=200 \\",
      "  -targets=attack.txt | vegeta report -type=json",
      "",
      "# note: the tool's 'throughput' field counts only successful responses,",
      "# so every arm that returns 403 reports zero. use the 'rate' field."])

H2("B.7  Resource measurement")
CODE(["# container processor time, covering every process inside the container",
      "PID=$(docker inspect <container> -f '{{.State.Pid}}')",
      "CG=/sys/fs/cgroup$(sed -n 's/^0:://p' /proc/$PID/cgroup)",
      "sed -n 's/^usage_usec //p' $CG/cpu.stat     # microseconds",
      "cat $CG/memory.current                      # bytes",
      "",
      "# native single process",
      "awk '{print $14+$15}' /proc/<pid>/stat      # clock ticks",
      "awk '/^VmRSS:/{print $2}' /proc/<pid>/status # KiB",
      "",
      "# divide processor time by requests ANSWERED and cores by REAL elapsed",
      "# time. BunkerWeb's attack arm runs ~50s of wall time, not the nominal",
      "# 20s, because it is still draining 30-second timeouts."])

PAGEBREAK()

# ================================ APPENDIX C ==============================
H1("C", "Appendix C — Terminology")

table(doc, ["Term", "Meaning as used in this document"], [
  ["Attack payload", "One crafted request from the test corpus that a correctly "
   "functioning web application firewall should refuse."],
  ["Legitimate request", "One ordinary request from the corpus that a correctly "
   "functioning web application firewall should allow. Also described in the industry "
   "as a true-negative test."],
  ["Composite score", "The test tool's headline figure: the mean of its application "
   "and API averages, where the application average is itself the mean of attacks "
   "refused and legitimate requests allowed."],
  ["Paranoia level", "A sensitivity setting in the OWASP Core Rule Set. Higher levels "
   "enable additional rules that detect more attacks and also match more legitimate "
   "traffic."],
  ["Anomaly threshold", "The accumulated score at which Swaraj Kavach refuses "
   "a request. Individual detections contribute scores; the request is refused when "
   "the total reaches the threshold."],
  ["Semantic analysis", "SafeLine's detection method, which parses request content and "
   "judges its structure rather than matching it against a corpus of signatures."],
  ["Open loop", "A load-generation mode in which the generator issues requests as fast "
   "as the target will accept them, revealing the target's own limit."],
  ["99th percentile latency", "The response time that 99 per cent of requests came in "
   "under. A more useful measure of user experience than an average, because it "
   "describes the slow tail rather than the typical case."],
  ["Processor time per request", "Processor seconds consumed divided by requests "
   "actually answered. A direct measure of how much hardware a given request rate "
   "requires."],
  ["Refusal response size", "The number of bytes a product returns when it blocks a "
   "request. Large refusal pages dominate throughput measurements under attack."],
], widths=[3.6, 12.0], align=["l","l"], font=8.5, mono=False)

doc.add_paragraph().paragraph_format.space_after = Pt(18)
hrule(P(after=6), "C9D2CF", 6)
RICH([("Document ends. ", True),
      (f'{M["product"]} — {M["title"]}, version {M["version"]}, {M["date"]}. '
       f'Prepared by {M["author"]}, {M["unit"]}, {M["org"]}. {M["classif"]}.', False)], size=8.5)

out = os.path.join(HERE, "ESDS-WAF-Benchmark-Report-v1.0.docx")
doc.save(out)
print("saved:", out, os.path.getsize(out), "bytes")
