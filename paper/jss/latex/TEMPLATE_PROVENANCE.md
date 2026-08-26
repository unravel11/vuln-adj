# Elsevier/JSS LaTeX Source Provenance

**Checked:** 2026-08-26

- The source uses the installed Elsevier-maintained `elsarticle` class, version
  3.5 (TeX Live package revision 77318, dated 2026-01-09).
- Official Elsevier LaTeX instructions identify `elsarticle` as the supported
  class and require the editable source archive. They also state that source
  files submitted through Editorial Manager should be kept at one directory
  level because subfolders are not processed reliably.
- The source directory is therefore flat: `main.tex`, `references.bib`, three
  table fragments, and their CSV companions are siblings.
- The official Elsevier downloadable example bundle was checked in `/tmp` only
  (SHA-256 `0b093093e84db49f99bcc9a7c3f69ed1fb61b0147c6d296427aff7963e7f50f6`).
  It was not vendored because the installed maintained class is newer and the
  paper does not need copied example content.
- JSS author-anonymization handling remains `UNRESOLVED_RECHECK_LIVE`. This
  preparation source uses placeholder author metadata and makes no claim about
  the journal's review mode.
- A successful local compile checks source compatibility and layout only. It
  does not establish scientific validity, author approval, submission
  readiness, or acceptance.

Official sources:

- <https://www.elsevier.com/researcher/author/policies-and-guidelines/latex-instructions>
- <https://ctan.org/texarchive/macros/latex/contrib/elsarticle>
- <https://shop.elsevier.com/journals/journal-of-systems-and-software/0164-1212>
