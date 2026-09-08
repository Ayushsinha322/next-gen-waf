"""Low-level docx helpers: styling, shaded tables, fields, callouts."""
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt, Cm, RGBColor, Emu

# ESDS report palette
INK    = RGBColor(0x11, 0x1A, 0x19)
INK2   = RGBColor(0x3D, 0x4B, 0x49)
MUTED  = RGBColor(0x66, 0x75, 0x6F)
ACCENT = RGBColor(0x0A, 0x6A, 0x5C)
BAD    = RGBColor(0x8E, 0x2F, 0x2F)
WARN   = RGBColor(0x9C, 0x53, 0x22)
WHITE  = RGBColor(0xFF, 0xFF, 0xFF)
SH_HEAD, SH_ZEBRA, SH_GROUP, SH_OURS, SH_BOX, SH_WARNBOX = \
    "0A6A5C", "F2F6F5", "E3EAE8", "E2EFEC", "F4F7F6", "FBF3EC"

BODY_FONT, MONO_FONT = "Lato", "DejaVu Sans Mono"


def set_font(run, name=BODY_FONT, size=10, color=INK, bold=False, italic=False):
    run.font.name = name
    run.font.size = Pt(size)
    run.font.color.rgb = color
    run.bold = bold
    run.italic = italic
    rpr = run._element.get_or_add_rPr()
    rf = rpr.find(qn("w:rFonts"))
    if rf is None:
        rf = OxmlElement("w:rFonts"); rpr.append(rf)
    for a in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        rf.set(qn(a), name)
    return run


def shade(cell, hexcolor):
    tcpr = cell._tc.get_or_add_tcPr()
    el = OxmlElement("w:shd")
    el.set(qn("w:val"), "clear"); el.set(qn("w:color"), "auto")
    el.set(qn("w:fill"), hexcolor)
    tcpr.append(el)


def cell_borders(cell, top=None, bottom=None, left=None, right=None, size=4):
    tcpr = cell._tc.get_or_add_tcPr()
    borders = OxmlElement("w:tcBorders")
    for edge, col in (("top", top), ("bottom", bottom), ("left", left), ("right", right)):
        e = OxmlElement(f"w:{edge}")
        if col is None:
            e.set(qn("w:val"), "nil")
        else:
            e.set(qn("w:val"), "single"); e.set(qn("w:sz"), str(size))
            e.set(qn("w:space"), "0"); e.set(qn("w:color"), col)
        borders.append(e)
    tcpr.append(borders)


def cell_margins(cell, top=60, bottom=60, left=100, right=100):
    tcpr = cell._tc.get_or_add_tcPr()
    m = OxmlElement("w:tcMar")
    for k, v in (("top", top), ("bottom", bottom), ("left", left), ("right", right)):
        e = OxmlElement(f"w:{k}")
        e.set(qn("w:w"), str(v)); e.set(qn("w:type"), "dxa")
        m.append(e)
    tcpr.append(m)


def no_space(par, before=0, after=0, line=None):
    pf = par.paragraph_format
    pf.space_before = Pt(before); pf.space_after = Pt(after)
    if line: pf.line_spacing = line
    return par


def keep_with_next(par):
    par.paragraph_format.keep_with_next = True
    return par


def field(par, code):
    """Insert a Word field (PAGE, NUMPAGES) that LibreOffice renders on convert."""
    r = par.add_run()
    f1 = OxmlElement("w:fldChar"); f1.set(qn("w:fldCharType"), "begin")
    it = OxmlElement("w:instrText"); it.set(qn("xml:space"), "preserve"); it.text = code
    f2 = OxmlElement("w:fldChar"); f2.set(qn("w:fldCharType"), "end")
    r._r.append(f1); r._r.append(it); r._r.append(f2)
    return r


def hrule(par, color="C9D2CF", size=8):
    ppr = par._p.get_or_add_pPr()
    b = OxmlElement("w:pBdr")
    e = OxmlElement("w:bottom")
    e.set(qn("w:val"), "single"); e.set(qn("w:sz"), str(size))
    e.set(qn("w:space"), "6"); e.set(qn("w:color"), color)
    b.append(e); ppr.append(b)
    return par


def callout(doc, tag, lines, accent=True):
    """A single-cell shaded box with a coloured left edge."""
    t = doc.add_table(rows=1, cols=1)
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    c = t.cell(0, 0)
    shade(c, SH_BOX if accent else SH_WARNBOX)
    cell_borders(c, left="0A6A5C" if accent else "9C5322", size=18)
    cell_margins(c, top=140, bottom=140, left=180, right=180)
    p = c.paragraphs[0]; no_space(p, after=4)
    set_font(p.add_run(tag.upper()), MONO_FONT, 7.5,
             ACCENT if accent else WARN, bold=True)
    for i, ln in enumerate(lines):
        par = c.add_paragraph(); no_space(par, before=3 if i else 3, after=0, line=1.25)
        for seg, bold in ln if isinstance(ln, list) else [(ln, False)]:
            set_font(par.add_run(seg), BODY_FONT, 9.5, INK2, bold=bold)
    doc.add_paragraph().paragraph_format.space_after = Pt(4)
    return t


def table(doc, headers, rows, widths=None, align=None, caption=None,
          note=None, font=8.5, group_rows=(), ours_rows=(), col_colors=None,
          mono=True):
    """headers: list[str]; rows: list[list[str]]. align: 'l'/'r'/'c' per column."""
    if caption:
        p = doc.add_paragraph(); no_space(p, before=8, after=3); keep_with_next(p)
        set_font(p.add_run(caption), MONO_FONT, 7.5, MUTED, bold=True)
    t = doc.add_table(rows=1, cols=len(headers))
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    align = align or (["l"] + ["r"] * (len(headers) - 1))
    amap = {"l": WD_ALIGN_PARAGRAPH.LEFT, "r": WD_ALIGN_PARAGRAPH.RIGHT,
            "c": WD_ALIGN_PARAGRAPH.CENTER}

    hdr = t.rows[0]
    hdr.cells[0]._tc.getparent().set(qn("w:tblHeader"), "1") if False else None
    trpr = hdr._tr.get_or_add_trPr()
    th = OxmlElement("w:tblHeader"); trpr.append(th)          # repeat on page break
    for i, h in enumerate(headers):
        c = hdr.cells[i]; shade(c, SH_HEAD)
        cell_borders(c, bottom="0A6A5C")
        cell_margins(c, top=70, bottom=70)
        p = c.paragraphs[0]; no_space(p); p.alignment = amap[align[i]]
        set_font(p.add_run(h), BODY_FONT, font - 0.7, WHITE, bold=True)

    for ri, row in enumerate(rows):
        r = t.add_row()
        is_group = ri in group_rows
        is_ours = ri in ours_rows
        for i, v in enumerate(row):
            c = r.cells[i]
            if is_group:   shade(c, SH_GROUP)
            elif is_ours:  shade(c, SH_OURS)
            elif ri % 2:   shade(c, SH_ZEBRA)
            cell_borders(c, bottom="DDE4E1")
            cell_margins(c, top=52, bottom=52)
            p = c.paragraphs[0]; no_space(p); p.alignment = amap[align[i]]
            txt = str(v)
            col = INK
            if col_colors and (ri, i) in col_colors: col = col_colors[(ri, i)]
            bold = is_group or is_ours or (col_colors and (ri, i) in col_colors)
            fname = BODY_FONT if (i == 0 or not mono) else MONO_FONT
            if is_group: fname = BODY_FONT
            set_font(p.add_run(txt), fname, font - (0.8 if is_group else 0), col,
                     bold=bold)
    if widths:
        # Fixed layout, or LibreOffice and Word both auto-fit and ignore the widths.
        t.autofit = False
        tblpr = t._tbl.tblPr
        lay = OxmlElement("w:tblLayout"); lay.set(qn("w:type"), "fixed"); tblpr.append(lay)
        grid = t._tbl.find(qn("w:tblGrid"))
        if grid is not None:
            for gc, w in zip(grid.findall(qn("w:gridCol")), widths):
                gc.set(qn("w:w"), str(int(Cm(w).twips)))
        for i, w in enumerate(widths):
            for row in t.rows:
                row.cells[i].width = Cm(w)
    if note:
        p = doc.add_paragraph(); no_space(p, before=4, after=10, line=1.2)
        set_font(p.add_run(note), BODY_FONT, 8, MUTED, italic=True)
    else:
        doc.add_paragraph().paragraph_format.space_after = Pt(6)
    return t


def figure(doc, path, caption, width_cm=16.0):
    p = doc.add_paragraph(); no_space(p, before=6, after=2)
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.add_run().add_picture(path, width=Cm(width_cm))
    cp = doc.add_paragraph(); no_space(cp, before=2, after=12)
    cp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    set_font(cp.add_run(caption), BODY_FONT, 8, MUTED, italic=True)
