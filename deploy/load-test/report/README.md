# Customer-facing benchmark report generator

Builds the enterprise comparison document (Swaraj Kavach vs BunkerWeb 1.6.9 vs
SafeLine 9.4.1) as a Word document, then a PDF. One source, both formats, so a
revision never means re-editing two files.

The measured numbers live in `content.py` and nowhere else. Change a figure there and
both outputs follow. Narrative and structure are in `build.py`.

Two documents are built from the same data:

| Output | Pages | Shape | Audience |
|---|---|---|---|
| `ESDS-WAF-Benchmark-Report-v1.0` | 24 | narrative, one row per configuration | technical evaluators, full evidence base, appendices |
| `Swaraj-Kavach-Benchmark-Summary-v1.0` | 2 | narrative, one row per configuration | executives, first customer contact |
| `Swaraj-Kavach-Competitive-Comparison-v1.0` | 2 | **matrix, one column per product** | competitive discussions, bid responses |

The comparison document is the one to reach for in a competitive conversation: rows are
dimensions and columns are products, so a reader compares across a row instead of
hunting between tables. Our column is shaded and bold; the best figure in each row is
green and each failure is red. Where a competitor has two sensitivity settings both
values appear in the cell, shipped default first.

```bash
pip install python-docx matplotlib      # only dependencies

python3 charts.py        && python3 build.py         # the 24-page report
python3 charts_brief.py  && python3 build_brief.py   # the 2-page summary
python3 build_matrix.py                              # the 2-page comparison matrix
libreoffice --headless --convert-to pdf *.docx
```

### Keeping the summary at exactly two pages

It is tuned to fill two pages with no third. The margins are 1.35 cm top and
1.55 cm sides, body text is 8.8 pt and tables 7.6 pt. Adding a figure or more than
about six lines of prose pushes it to three pages — a throughput chart was tried on
page 2 and had to be removed for exactly that reason. After any edit, check
`pdfinfo | grep Pages` before shipping.

## Why it is built this way

* **python-docx, not HTML to PDF.** The document has to be editable by people who are
  not engineers, and rebrandable without touching code. A Word file with real styles,
  a real header and footer and a real page-number field satisfies that; a printed web
  page does not.
* **LibreOffice for the PDF.** It renders the `PAGE` field, so page numbers are real
  rather than baked in.
* **Fixed table layout is mandatory.** Without `w:tblLayout = fixed` and explicit
  `w:gridCol` widths, both Word and LibreOffice auto-fit and silently ignore the
  column widths, which wrecks every wide table.
* **`NUMPAGES` is deliberately absent.** LibreOffice evaluated it one page high on
  conversion, and a wrong total in front of a customer is worse than no total.

## Editorial rules for this document

The report discloses, by design and in section 9: the open machine-learning
false-positive on login forms, the fact that our own benign corpus cannot detect it,
and every dimension on which a competitor beats us. Do not remove those to make the
document more flattering — the credibility of the other 23 pages depends on them, and
a customer who finds an undisclosed weakness later discounts everything else.

## Product naming

Customer-facing material names the product **Swaraj Kavach**, with the descriptor
"Next-Generation Web Application Firewall" on first mention only. `sentinel` is the
internal engineering codename and appears only in commands, configuration and log
output.

The name is a proper noun, so it takes no definite article: "Swaraj Kavach refuses",
never "the Swaraj Kavach refuses". Two traps when renaming: the article and the name
often sit in *different* adjacent string literals, and the old name was itself split
across a line break, so a plain search-and-replace on the source misses both. Verify a
rename against the rendered PDF with `pdftotext`, not against the source.


## The table helper

`build_helpers.table()` carries the column shading and per-cell colouring the matrix
document needs: `shade_cols={1: SH_OURS}` tints a whole column including its header,
`bold_cols=(1,)` bolds it, and `col_colors={(row, col): COLOUR}` marks winners and
failures individually.

One trap: the bold flag must be coerced with `bool()`. `is_group or (col_colors and ...)`
returns the empty dict when `col_colors` is `{}`, and python-docx rejects anything that
is not exactly True, False or None with a `TypeError` deep inside the XML layer.
