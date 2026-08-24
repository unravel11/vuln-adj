# Field-Level Discrepancy Typing across Aligned Vulnerability Databases

Status: working manuscript. This file is built from logged project evidence and reproducible artifact outputs. It treats all current measurements as baseline or silver-label outputs unless explicitly stated otherwise.

## Submission-Facing Draft Components

- [Abstract](abstract.md)
- [Highlights](highlights.md)
- [Title Page Draft](title_page.md)
- [Introduction](sections/01_introduction.md)
- [Background and Problem Definition](sections/02_background_problem_definition.md)
- [Method](sections/03_method.md)
- [Experimental Setup](sections/04_experimental_setup.md)
- [Results](sections/05_results.md)
- [Discussion](sections/06_discussion.md)
- [Threats to Validity](sections/07_threats_to_validity.md)
- [Related Work](sections/08_related_work.md)
- [Conclusion](sections/09_conclusion.md)
- [References Draft](references.md)
- [Declarations Draft](declarations.md)

## Internal Planning Files

These files are for project coordination only and must not be included in a journal submission package:

- [Cover Letter Preparation Draft](cover_letter_draft.md)
- [Submission Readiness Checklist](submission_readiness.md)

## Draft Summary

The assembled full Markdown draft is generated at `paper/cose/full_draft.md` by `experiments/paper_artifacts/build_cose_manuscript.py`.

Draft BibTeX is generated at `paper/cose/references.bib` by `experiments/paper_artifacts/build_cose_bibtex.py`.

The generated Elsevier/elsarticle LaTeX scaffold is built at `paper/cose/latex/main.tex` by `experiments/paper_artifacts/build_cose_latex.py`; the last verified local build produced `paper/cose/latex/main.pdf`.

Submission packaging gaps are tracked in `paper/cose/submission_readiness.md`; current highlights are in `paper/cose/highlights.md`.

The project starts from an aligned corpus of 100,032 normalized NVD records, 28,785 normalized GHSA records, and 8,066 CVE-ID pairs. The core observation is that alignment does not remove disagreement: the current deterministic baseline still reports substantial severity and affected_versions conflicts, while published and references often fall into temporal, representation, or incomplete categories. The cwe_ids field is mostly equivalent but still has a smaller conflict/incompleteness tail. The reproducible summary tables are generated in `results/paper_cose/cose_artifact_tables.md`, and the RQ1 deterministic distribution is also materialized as `paper/cose/figures/rq1_discrepancy_heatmap.svg` plus `paper/cose/tables/rq1_discrepancy_distribution.md`.

The current RQ3 prototype has silver-only diagnostic comparisons for severity and affected_versions. The severity setup uses an 80-sample silver-v2 seed, 470 candidate evidence URLs, and a cached evidence corpus; on that seed, the logged evidence-score baseline has higher silver-label agreement than fixed-source diagnostic baselines. The affected_versions setup uses 100 evidence-aware LLM silver labels and a simple version-token support baseline. Both comparisons remain selective and silver-labeled, not human gold.

The manuscript therefore stays conservative. It documents the problem, the type-first baseline pipeline, a non-gold RQ2 rule-trigger diagnostic, the prepared-but-unlabeled RQ2 annotation seed, the provisional severity adjudication experiment, affected_versions silver-label composition, generated paper-facing case-study sketches, and the main validity threats, while keeping RQ2 accuracy and gold-backed adjudication claims open until the missing labels and audit steps are finished.
