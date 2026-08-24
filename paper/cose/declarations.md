# Submission Declarations Draft

Status: draft placeholders for Computers & Security submission packaging. These statements must be reviewed and completed by the authors before submission.

## Data and Code Availability

Draft statement:

The experiments in this manuscript are based on normalized NVD and GitHub Security Advisory records aligned by CVE identifier. The repository contains scripts, generated manifests, discrepancy statistics, paper tables, and annotation templates used to reproduce the reported baseline and silver-label analyses. Raw upstream data may be subject to the availability and licensing terms of the original NVD and GitHub sources. Final submission should include a stable repository URL or artifact archive DOI.

Repository artifacts currently referenced by the draft include:

- `data/processed/bootstrap/discrepancies/field_discrepancy_stats.json`
- `data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl`
- `results/paper_cose/cose_artifact_tables.md`
- `results/paper_cose/cose_case_studies.md`
- `data/annotations/rq2/discrepancy_typing_seed.jsonl`
- `data/annotations/rq3/silver_v2/`
- `experiments/`
- `scripts/`

## Declaration of Competing Interest

TODO: Authors must declare any financial or personal relationships that could influence the work. If none exist, use an author-approved "no competing interests" statement.

## Funding

TODO: Add grant names, grant numbers, funder roles, or an author-approved "no funding" statement.

## CRediT Author Statement

TODO: Add author contributions after author list is final.

Suggested roles to consider:

- Conceptualization
- Methodology
- Software
- Validation
- Formal analysis
- Investigation
- Data curation
- Writing - original draft
- Writing - review and editing
- Visualization
- Supervision
- Project administration
- Funding acquisition

## Declaration of Generative AI and AI-Assisted Technologies

Draft statement to review:

During preparation of this manuscript, generative AI tools were used to assist with manuscript drafting, code scaffolding, and provisional evidence-aware silver-label generation. The authors remain responsible for the final content, interpretation, and verification of all claims. The current manuscript treats AI-generated or AI-assisted labels as silver labels, not human gold. Final submission should disclose the exact tools and usage according to the journal's current policy.

## Ethics and Human Annotation

The RQ2 annotation seed and RQ3 adjudication samples are based on public vulnerability records and advisory references. Human annotation, once performed, should follow `docs/annotation_guidelines/rq2_discrepancy_typing.md` and should not treat deterministic baseline labels as ground truth. If additional annotators are used, record disagreement handling and any consistency checks in the final manuscript.
