# Customer-facing benchmark report generator

Builds the enterprise comparison document (Swaraj Kavach vs BunkerWeb 1.6.9 vs
SafeLine 9.4.1) as a Word document, then a PDF. One source, both formats, so a
revision never means re-editing two files.

The measured numbers live in `content.py` and nowhere else. Change a figure there and
both outputs follow. Narrative and structure are in `build.py`.

```bash
pip install python-docx matplotlib          # only dependencies
python3 charts.py                           # writes figs/*.png at 200 dpi
python3 build.py                             # writes ESDS-WAF-Benchmark-Report-v1.0.docx
libreoffice --headless --convert-to pdf ESDS-WAF-Benchmark-Report-v1.0.docx
```

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
