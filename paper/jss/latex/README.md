# JSS Editable LaTeX Zero Draft

This flat directory is the editable Elsevier/JSS preparation source. It is a
result-neutral zero draft, not an author-approved or submission-ready
manuscript.

Roles:

- `../manuscript.md` is the prose/claim authority at stage
  `S2_ARGUMENT_LOCKED`.
- `main.tex` is the synchronized venue-source representation used to compile
  and visually inspect that zero draft.
- `references.bib` and `../CITATION_EVIDENCE_MAP_20260826.md` bind citations to
  checked metadata and local evidence levels.
- the CSV and table fragments are generated from the label-free deterministic
  census by:

  `python experiments/paper_artifacts/build_jss_deterministic_tables.py`

Compile from this directory:

```sh
latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex
```

The build must leave the abstract, RQ3 results, and conclusion placeholders in
place until valid real-human E08/E09 evidence exists. Do not put reviewer
returns, reason/calibration-2/formal packets, or private analyst materials in
this source directory.
