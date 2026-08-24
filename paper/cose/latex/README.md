# COSE LaTeX Scaffold

This directory is generated from the Markdown manuscript and paper artifacts.
Markdown remains the source of record; rerun the generator after editing sections.

Build from the repository root:

```bash
.venv/bin/python -m pip install -r experiments/paper_artifacts/requirements.txt
.venv/bin/python experiments/paper_artifacts/build_cose_bibtex.py
.venv/bin/python experiments/paper_artifacts/build_cose_latex.py
cd paper/cose/latex
latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex
```

Claim boundaries to preserve:

- RQ1 is a deterministic baseline distribution, not a gold distribution.
- RQ2 is a diagnostic plus blank annotation templates until human labels exist.
- RQ3 uses evidence-aware silver labels, not human gold.
- `affected_versions` is currently a token-support prototype, not semantic version adjudication.
- Journal policy and generative-AI use remain author-review and declaration items.
