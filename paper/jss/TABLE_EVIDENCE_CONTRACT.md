# JSS Deterministic Table Evidence Contract

**Frozen source:** `results/jss/t1_routing_precheck_v1/analysis.json`
**Source SHA-256:** `47428580744f0d83331c15b82a623a771f40a40d1ddcf59731fd83787553f7a8`
**Generator:** `experiments/paper_artifacts/build_jss_deterministic_tables.py`

## Claim and data contract

- Unit for RQ1: one field instance in one of four fields for each of 8,066
  CVE-aligned NVD--GHSA rows.
- Unit for RQ2: the action emitted by one frozen strategy for one field instance.
- Population displayed: the complete deterministic census of 32,264 field
  instances, not a sample.
- Missing category keys in the source JSON are interpreted as zero only after
  each field/status row and strategy/field action row sums to 8,066.
- No uncertainty interval is shown because the tables report a complete
  deterministic census. This does not remove uncertainty about rule validity or
  external generalization.
- `manual total = conflict_escalation + abstain`. It is a routing count, not
  elapsed labor, cost, workload, correctness, safety, or utility.
- Tables must not apply winner styling, superiority symbols, significance marks,
  causal wording, or human-ground-truth language.

## Table jobs

| Artifact | Reader lookup job | Claim ceiling |
|---|---|---|
| `rq1_status_counts.csv` / `table_rq1_status_counts.tex` | Exact field-by-status counts | Snapshot- and rule-bounded descriptive result |
| `rq2_strategy_actions.csv` / `table_rq2_strategy_actions.tex` | Exact action allocation for each main strategy | Deterministic routing allocation only |
| `rq2_pairwise_disagreements.csv` / `table_rq2_pairwise_disagreements.tex` | Where strategy actions differ by field | Difference count, not error/correctness |

## Rendering decision and audit trail

`pubtab==1.0.1` was installed only in the isolated temporary environment
`/tmp/vuln-adj-pubtab-1.0.1`; no repository interpreter or lockfile was changed.
Its `xlsx2tex` conversion reproduced the checked values. The first invocation
used a non-existent `--without-resizebox` flag and therefore did not produce a
table. A corrected invocation produced the three LaTeX fragments, but
`--preview` failed in the current TeX Live 2026 environment because the
standalone preview wrapper's caption/minipage combination did not compile.

The repository therefore uses the small native generator above as the
authoritative path. Visual acceptance requires compilation inside the real
`elsarticle` manuscript, PDF rendering, and page inspection. The failed
standalone preview is not evidence that the final tables render correctly.
