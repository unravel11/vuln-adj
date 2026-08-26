# JSS Zero-Draft Build Report

**Build date:** 2026-08-26
**Authority host:** `code-defender`
**Repository:** `/home/xiaoyuliang/code/vuln-adj`
**Branch:** `codex/jss-zero-draft-venue-20260825`
**Pre-package clean/upstream-synchronized HEAD:** `2334ecf5c07608873a0438127344954175fb4d48`

## Toolchain and command

- `elsarticle`: version 3.5, dated 2026-01-09, TeX Live revision 77318
- `latexmk`: 4.88
- `pdfTeX`: 1.40.29
- bibliography style: `elsarticle-harv`
- build command:

  `latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=<temporary-directory> main.tex`

The final checked build was written to a temporary directory and was not copied
into the repository.

## Mechanical result

- PDF pages: 22
- page size: 612 x 792 pt (US Letter under the preparation class defaults)
- PDF SHA-256:
  `0b88cda988422b2fc3b2fba1a9840ea7335f2deffcf4371db37847594908d269`
- undefined citations: 0
- undefined references: 0
- LaTeX/package warnings matched by the audit: 0
- overfull boxes: 0
- extracted-text scan for `??`, `Citation`, or `undefined`: clean
- extracted text retains the RQ3, conclusion, and author-owned declaration
  placeholders

## Visual verification

All 22 PDF pages were rendered to PNG at 120 dpi and inspected in four contact
sheets covering pages 1--6, 7--12, 13--18, and 19--22. Pages 13, 19, 21, and 22
were additionally inspected at the original rendered resolution because they
contain the deterministic tables, declarations, and dense references.

Observed result:

- no clipped or overlapping body text;
- all three deterministic tables stay within the text block and remain legible;
- captions, notes, page numbers, section headings, and references render;
- explicit result and author placeholders remain visible;
- no blank or duplicate page was observed.

## Evidence boundary

This report establishes that the current editable zero draft compiles and that
the rendered PDF passed a layout inspection. It does not establish author
approval, human-result validity, scientific correctness, a final journal page
count, submission readiness, or acceptance. The PDF is a temporary QA artifact,
not the final submission PDF.
