# Evidence Ledger

Status values follow the paper workflow contract. A file or validator is
evidence only for the condition it directly checks.

| Evidence ID | Source | Status | Protocol or population | What it supports | What it cannot support | Validation |
|---|---|---|---|---|---|---|
| E01 | `data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl` | `VERIFIED_CURRENT` | 8,066 CVE-ID-aligned NVD–GHSA rows; five field views per row | Frozen-corpus RQ1 counts and deterministic baseline outputs | Human discrepancy truth, database quality, causal explanation, broader prevalence | SHA-256 `c4bb4053...cc3a2`; 8,066 rows verified 2026-08-23 |
| E02 | `data/annotations/rq2/discrepancy_typing_seed.jsonl` | `VERIFIED_CURRENT` as a sampling frame | Stratified random seed, 60 rows per field, 300 total | A bounded T1 sampling frame with known baseline strata | Human gold, blinded review, unweighted population prevalence | 300 unique IDs, 300 blank labels, 300/300 exact current-row binding; SHA-256 `2b70d0c4...a518f` |
| E03 | `data/annotations/rq2/sample_manifest.json` and `scripts/build_rq2_annotation_samples.py` | `CONTROLLED_OR_RETROSPECTIVE` | Equalized allocation over available deterministic baseline strata | Initial seed, candidate counts, and inclusion-stratum reconstruction | A sealed T1 packet: the old manifest lacks source hashes and old templates expose baseline labels | Manifest SHA-256 `4dff7bb1...f3bae`; builder inspected 2026-08-23 |
| E04 | Existing RQ2 AI candidate, consistency, tiebreak, and evidence-secondary outputs | `CONTROLLED_OR_RETROSPECTIVE` | Same-model-family, multi-pass, partly post-unsealing diagnostics | Failure modes, abstention behavior, protocol history, and experiment design | Independent human agreement, human-gold accuracy, confirmation, production promotion | Non-human boundaries and stop rules recorded in project plan and COSE package |
| E05 | `results/holdout/rq2_post_profile_snapshot_v1/` and identifiability analyses | `CONTROLLED_OR_RETROSPECTIVE` | Revealed snapshot-external 250-row cohort; profile differences on only three rows | Effect-size and paired-test identifiability limits for that fixed comparison | Future prevalence, temporal generalization, correctness, equivalence of methods | Exhaustive assignment diagnostic: minimum two-sided exact McNemar p = 0.25 |
| E06 | Existing RQ3 severity and affected-version v2 outputs | `CONTROLLED_OR_RETROSPECTIVE` | Non-human adjudication cohorts with explicit abstention and baselines | Bounded negative results, low coverage, evidence dependence, and failure analysis | A successful adjudication method, general NVD superiority, human-backed source truth | Current affected-version primary methods did not exceed named baselines |
| E07 | `results/paper_cose/cose_package_manifest.json` | `VERIFIED_CURRENT` for the dated package only | COSE package build and validation snapshot dated 2026-07-19 | That the recorded package passed 127 mechanical checks | Current JSS science, current files, human labels, metadata, submission readiness | Manifest says `submission_ready=false` |
| E08 | T1 dual-human labels and adjudicated gold | `MISSING_OR_UNRESOLVED` | Two different real reviewers plus resolving author | RQ2 construct reliability and human-backed baseline evaluation | Nothing until all gates and signatures complete | Protocol exists; labels do not |
| E09 | T2 binary-versus-type-first utility results | `MISSING_OR_UNRESOLVED` | Frozen T1 evaluation labels; fixed action mapping | Workload, conflict recall, unnecessary escalation, and abstention trade-offs | Nothing until T1 is frozen and T2 code/protocol is sealed | Not yet implemented or run |
| E10 | Bilateral post-freeze temporal cohort | `MISSING_OR_UNRESOLVED` | Existing event-time rule requires at least 25 strict unique CVEs | Future-snapshot evaluation if eligibility is later met | Temporal validation from current data | Latest dated check had zero strict unique CVEs; decision remains wait |
| E11 | TOSEM aspect-level discrepancy study, VuldiffFinder, and affected-version tool benchmark | `VERIFIED_CURRENT` for positioning | Closest published work checked 2026-08-23 | Novelty ceiling and required baseline/related-work comparisons | Empirical support for this paper's method | Primary publisher or paper records were checked; detailed synthesis remains to be written |

## Evidence combination rule

E01–E07 may support a bounded empirical audit and negative/failure narrative.
They may not be combined to simulate E08 or E09. T1 and T2 remain missing even
if every existing package validator passes.
