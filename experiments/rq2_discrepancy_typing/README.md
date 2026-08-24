# RQ2: Discrepancy Typing

目标：

- 实现 deterministic normalization
- 实现字段级比较规则
- 评估五分类 typing 性能

建议后续放入：

- normalization rules
- field comparators
- evaluation scripts

## JSS V3 routing precheck and prepare-only human packet

The active low-human JSS route first runs a label-free full-corpus census of a
strong field-aware simple comparator, the current type-first efficiency arm,
and an abstention-aware safety arm. Raw and canonical non-equality are lower
references only.

```bash
python -m unittest discover \
  -s experiments/rq2_discrepancy_typing -p 'test_*routing_precheck.py'
python experiments/rq2_discrepancy_typing/analyze_t1_routing_precheck.py
python experiments/rq2_discrepancy_typing/verify_t1_routing_precheck.py
```

The frozen 8,066-row census returns
`CONDITIONAL_GO_FOR_V3_PACKET_DESIGN`. The strong-simple versus
abstention-aware comparison has 2,332 action differences. The safety arm has
74 fewer conflict escalations but 950 more total manual-review routes when
abstention is counted. These are deterministic policy outputs, not human-
validated correctness, safety, workload, or utility.

V3 uses the same two independent trained analysts and the same 120 formal cases
for action and reason judgments. Actions are completed and locked before reason
packets are released.

```bash
python -m unittest discover \
  -s experiments/rq2_discrepancy_typing \
  -p 'test_*t1_human_validation_packet_v3.py'
python experiments/rq2_discrepancy_typing/build_t1_human_validation_packet_v3.py
python experiments/rq2_discrepancy_typing/validate_t1_human_validation_packet_v3.py
python experiments/rq2_discrepancy_typing/validate_t1_human_validation_packet_v3.py \
  --require-distribution-ready
```

The normal validator must pass. The distribution-ready command must fail while
the manifest remains prepare-only. Current outputs are under:

- `results/jss/t1_routing_precheck_v1/`
- `data/annotations/rq2/t1_human_validation_v3/`

The V3 directory contains 20 calibration and 120 formal cases per reviewer,
separate action/reason stages, and zero human labels. Do not distribute it
until the guideline, reviewer roles, ethics/recruitment disposition, return
validators, evaluator, and author-approved distribution revision are frozen.
The older V2 packet is retained unchanged for audit and is not the active
distribution route.

## References normalization candidate diagnostic

`analyze_reference_normalization_variants.py` compares four incremental URL-normalization variants against the isolated RQ2 AI expert candidates and the full `8,066`-pair field view. It reports primary-pass, same-model review-pass, repeated-consensus, and full-corpus impact separately.

Run on the authoritative remote host:

```bash
python3 experiments/rq2_discrepancy_typing/test_reference_normalization_variants.py
python3 experiments/rq2_discrepancy_typing/analyze_reference_normalization_variants.py
python3 experiments/rq2_discrepancy_typing/merge_reference_normalization_dual_reviews.py
python3 experiments/rq2_discrepancy_typing/validate_reference_normalization_profile_v2.py
```

Outputs:

- `results/rq2_discrepancy_typing/reference_normalization_variant_diagnostic.json`
- `results/rq2_discrepancy_typing/reference_normalization_variant_diagnostic.md`
- `results/rq2_discrepancy_typing/reference_normalization_changed_cases.review.jsonl`
- `results/rq2_discrepancy_typing/reference_normalization_dual_ai_candidate.jsonl`
- `results/rq2_discrepancy_typing/reference_normalization_dual_ai_review.{json,md}`
- `results/rq2_discrepancy_typing/reference_normalization_v2/profile_validation.{json,md}`

The experiment is candidate-guided and keeps `label_is_human=false`. It does not update the production baseline or provide human-gold performance.

### References full-impact evidence audit and audited profile

The follow-up audit covers all 56 RD-to-INC changes from the original profile.
It recomputes every derived set/status, binds the exact changed-CVE set, freezes
118 URL probes, and gives two new reviewers all 56 transformation-masked rows.
Network certificates are auxiliary evidence; they do not bypass dual review.

```bash
python3 -m unittest \
  experiments/rq2_discrepancy_typing/test_build_reference_normalization_impact_validation.py \
  experiments/rq2_discrepancy_typing/test_merge_reference_normalization_impact_validation.py \
  experiments/rq2_discrepancy_typing/test_analyze_reference_normalization_audited_profile.py
python3 experiments/rq2_discrepancy_typing/build_reference_normalization_impact_validation.py
python3 experiments/rq2_discrepancy_typing/merge_reference_normalization_impact_validation.py
python3 experiments/rq2_discrepancy_typing/analyze_reference_normalization_audited_profile.py
```

Outputs:

- `results/rq2_discrepancy_typing/reference_normalization_impact_validation/`
- `results/rq2_discrepancy_typing/reference_normalization_audited_profile/`
- `results/rq2_discrepancy_typing/reference_normalization_impact_validation_superseded_hidden_contract/`

The valid E2/F2 runs reach strict consensus on `32/56` rows. They agree on all
five HTTP-to-HTTPS rows, four scoped Liferay-query rows, 17 GitHub-advisory
aliases, and six Huntr aliases. They disagree on all 24 rows affected by encoded
GitHub line-suffix stripping. The post-audit `resource_identity_audited_v1`
development profile therefore excludes line stripping and changes exactly the
32 strict-supported rows among 8,066 pairs. This selection is post-audit,
same-model-family, and non-human; production remains on `current`.

The retained superseded directory records a protocol pilot whose validator
contained confidence constraints absent from its sealed prompt. Its outputs are
excluded rather than mechanically repaired or reused.

### References real-human review gate

The complete 56-row impact set has a separate blank three-stage packet for real
human review. It is bound to the revision-2 seal and masked URL/probe worklist;
no E2/F2 decision is copied into a human field. The 24 encoded-line rows are
prioritized as `definition_sensitive`, but all 56 rows require final signoff.

```bash
python3 experiments/rq2_discrepancy_typing/test_validate_reference_normalization_human_review.py
python3 experiments/rq2_discrepancy_typing/build_reference_normalization_human_review_packet.py
python3 experiments/rq2_discrepancy_typing/validate_reference_normalization_human_review.py
python3 experiments/rq2_discrepancy_typing/validate_reference_normalization_human_review.py --require-signed
python3 experiments/rq2_discrepancy_typing/validate_reference_normalization_human_review.py --require-complete
```

Inputs and outputs:

- `data/annotations/rq2/reference_normalization_impact_human_review/reference_normalization_impact_human_review.jsonl`
- `data/annotations/rq2/reference_normalization_impact_human_review/reference_normalization_impact_human_review.csv`
- `results/rq2_discrepancy_typing/reference_normalization_impact_human_review/reference_normalization_human_review_readiness.{json,md}`

Every annotator, independent reviewer, and resolving author must explicitly use
`underlying_content_resource`, `frozen_http_resource`, or a written custom
definition. The validator also enforces exact group decisions, verdict-to-status
mapping, distinct human reviewer IDs, source hashes, and author signoff. The
packet currently has `56` pending rows and `0` signed rows. Its normal integrity
check passes, while both signed/complete gates intentionally reject it; rebuilding
also refuses to overwrite the existing review files.

## CWE taxonomy candidate diagnostic

`analyze_cwe_taxonomy_variants.py` parses the official CWE 4.20 Research Concepts view (`View_ID=1000`) and tests a conservative variant: change a disjoint `factual_conflict` to `representation_discrepancy` only when every CWE on both sides participates in an official ancestor/descendant path.

Run on the authoritative remote host:

```bash
python3 experiments/rq2_discrepancy_typing/analyze_cwe_taxonomy_variants.py
python3 experiments/rq2_discrepancy_typing/merge_cwe_taxonomy_dual_review.py
```

Outputs:

- `results/rq2_discrepancy_typing/cwe_taxonomy/cwe_taxonomy_variant_diagnostic.{json,md}`
- `results/rq2_discrepancy_typing/cwe_taxonomy/cwe_taxonomy_changed_cases.jsonl`
- `results/rq2_discrepancy_typing/cwe_taxonomy/cwe_taxonomy_dual_review_worklist.blind.jsonl`
- `results/rq2_discrepancy_typing/cwe_taxonomy/cwe_taxonomy_dual_ai_candidate.jsonl`
- `results/rq2_discrepancy_typing/cwe_taxonomy/cwe_taxonomy_dual_ai_review.{json,md}`

The full-corpus variant changes `17/8,066` CWE rows. The original blinded disagreement batch covers only one of those 17 changed rows, so its support for that case cannot be generalized to the other 16.

The follow-up full-impact audit seals all 17 changed rows and both method
predictions before two new Codex reviewer files exist:

```bash
python3 experiments/rq2_discrepancy_typing/test_build_cwe_taxonomy_impact_holdout.py
python3 experiments/rq2_discrepancy_typing/test_merge_cwe_taxonomy_impact_holdout.py
python3 experiments/rq2_discrepancy_typing/build_cwe_taxonomy_impact_holdout.py
python3 experiments/rq2_discrepancy_typing/merge_cwe_taxonomy_impact_holdout.py
```

Outputs:

- `results/rq2_discrepancy_typing/cwe_taxonomy/impact_holdout/cwe_taxonomy_impact_worklist.blind.jsonl`
- `results/rq2_discrepancy_typing/cwe_taxonomy/impact_holdout/cwe_taxonomy_impact_predictions.sealed.jsonl`
- `results/rq2_discrepancy_typing/cwe_taxonomy/impact_holdout/cwe_taxonomy_impact_manifest.sealed.json`
- `results/rq2_discrepancy_typing/cwe_taxonomy/impact_holdout/cwe_taxonomy_impact_dual_codex_audit.{json,md}`
- `results/rq2_discrepancy_typing/cwe_taxonomy/impact_holdout/cwe_taxonomy_human_priority_worklist.blind.jsonl`

Sixteen of the 17 changed CVEs are disjoint from the 300-row primary seed.
The reviewers agree on `15/17` labels (kappa `0.8068`), and strict decision
consensus retains `11/17`. On the 10 strict rows that are primary-seed
disjoint, taxonomy/current agreement is `7/10` versus `3/10`; the `+40pp`
paired delta has a 95% row-bootstrap interval of `[-20,+80]pp` and exact sign
diagnostic `p=0.34375`. Nine rows are prioritized for human review: six
unresolved rows and three strict candidate regressions.

This is positive candidate evidence over the complete rule impact set, not a
representative-corpus or human-gold result. Both reviewers are separate Codex
runs from the same model family. The production default remains unchanged and
all outputs have `label_is_human=false`.

### CWE taxonomy evidence-enhanced secondary audit

The six unresolved rows and three strict candidate regressions from the first
full-impact audit are selected for a second, evidence-enhanced audit. The
builder freezes up to five ranked references listed by NVD or GHSA per row,
without exposing either method prediction or any first-stage reviewer label.
Two new isolated Codex runs use different review orders. Every determinate
decision must cite a literal substring from an `ok` frozen evidence record.

Run on the authoritative remote host:

```bash
python3 experiments/rq2_discrepancy_typing/test_build_cwe_taxonomy_evidence_secondary_audit.py
python3 experiments/rq2_discrepancy_typing/test_merge_cwe_taxonomy_evidence_secondary_audit.py
python3 experiments/rq2_discrepancy_typing/build_cwe_taxonomy_evidence_secondary_audit.py
python3 experiments/rq2_discrepancy_typing/merge_cwe_taxonomy_evidence_secondary_audit.py
```

Outputs:

- `results/rq2_discrepancy_typing/cwe_taxonomy/evidence_secondary_audit/cwe_taxonomy_evidence_secondary_worklist.blind.jsonl`
- `results/rq2_discrepancy_typing/cwe_taxonomy/evidence_secondary_audit/cwe_taxonomy_evidence_secondary_manifest.sealed.json`
- `results/rq2_discrepancy_typing/cwe_taxonomy/evidence_secondary_audit/cwe_taxonomy_evidence_secondary_candidate.jsonl`
- `results/rq2_discrepancy_typing/cwe_taxonomy/evidence_secondary_audit/cwe_taxonomy_evidence_combined_candidate.jsonl`
- `results/rq2_discrepancy_typing/cwe_taxonomy/evidence_secondary_audit/cwe_taxonomy_evidence_secondary_audit.{json,md}`

The frozen worklist contains 36 reference records, of which 28 were fetched
successfully. The secondary reviewers agree strictly on `7/9` rows; combined
with the eight non-priority first-stage strict rows, coverage becomes `15/17`
with 11 RD, four FC, and two unresolved rows. On 14 primary-seed-disjoint
strict rows, taxonomy/current agreement is `10/14` versus `4/14`; the paired
delta is `+42.86pp`, with a 95% row-bootstrap interval of `[0,+85.71]pp` and
exact sign diagnostic `p=0.1796`.

This is a post-hoc, impact-selected, evidence-availability-dependent diagnostic
from the same Codex model family. It is not human gold, independent
confirmation, or a production-switch result.

### CWE taxonomy real-human review gate

The complete 17-row impact set also has a blank three-stage packet for actual
human review. A row must contain a primary annotator decision, a decision from
a different human reviewer, and a signed author resolution. Codex candidate
labels are not prefilled.

Run on the authoritative remote host:

```bash
python3 experiments/rq2_discrepancy_typing/test_validate_cwe_taxonomy_human_review.py
python3 experiments/rq2_discrepancy_typing/validate_cwe_taxonomy_human_review.py
python3 experiments/rq2_discrepancy_typing/validate_cwe_taxonomy_human_review.py --require-signed
python3 experiments/rq2_discrepancy_typing/validate_cwe_taxonomy_human_review.py --require-complete
```

Inputs and outputs:

- `data/annotations/rq2/cwe_taxonomy_impact_human_review/cwe_taxonomy_impact_human_review.jsonl`
- `data/annotations/rq2/cwe_taxonomy_impact_human_review/cwe_taxonomy_impact_human_review.csv`
- `results/rq2_discrepancy_typing/cwe_taxonomy/impact_human_review/cwe_taxonomy_human_review_readiness.{json,md}`

The JSONL file is the authoritative editable packet consumed by the validator;
the CSV is a read-only convenience view and is not imported. The packet
currently has `17` pending rows and `0` signed rows. The normal schema check
passes, while both signed/complete gates intentionally reject it. Building the
packet again refuses to overwrite the existing files.

## Fresh-CVE typing stability holdout

`build_rq2_typing_holdout.py` freezes a current-snapshot diagnostic after
excluding all 717 CVEs previously exposed through RQ2/RQ3 development,
full-impact audits, and holdouts. It selects 250 rows per field with globally
unique CVEs, projects raw aligned source values into blind A/B worklists, and
seals six executable prediction profiles before review:

- `current`
- `reference_resource_identity_original_v1`
- `reference_resource_identity_audited_v1`
- `cwe_taxonomy_v1`
- `combined_original_v1`
- `combined_audited_v1`

```bash
python3 -m unittest discover \
  -s experiments/rq2_discrepancy_typing -p 'test_*.py'
python3 experiments/rq2_discrepancy_typing/build_rq2_typing_holdout.py --force
python3 experiments/rq2_discrepancy_typing/merge_rq2_typing_holdout_reviews.py
python3 experiments/rq2_discrepancy_typing/evaluate_rq2_typing_holdout.py
```

Sealed inputs are under `data/annotations/holdout/rq2_typing_v1/`. The current
manifest contains 1,250 rows and 1,250 unique CVEs, with 250 rows per field.
It binds `codex-cli 0.144.4`, the executable SHA-256, `gpt-5.5`, medium
reasoning, read-only sandboxing, and ephemeral sessions. Reviewer rows carry
thread ID and token usage, and the merge requires disjoint A/B session sets.
All six prediction columns are identical after the development-impact CVEs are
excluded. This makes candidate-profile gain unidentifiable on the current
snapshot; the cohort can only diagnose fresh-CVE baseline typing stability.
A confirmatory candidate comparison requires a future NVD-GHSA time cohort
collected after profile freeze.

The A/B passes are complete at 1,250 rows each. Exact label agreement is
1,167/1,250 (`0.9336`, kappa `0.9091`), and strict consensus retains
1,147/1,250 rows (`0.9176`). The current baseline has strict accuracy `0.8117`,
strict macro-F1 `0.8293`, and full-cohort lower-bound accuracy `0.7448`.
Per-field strict accuracy is `1.0000` for published, `0.9916` for references,
`0.9913` for cwe_ids, `0.7552` for affected_versions, and `0.3096` for severity.
All six prediction profiles remain identical, so these are baseline-stability
results rather than a candidate comparison. The two pass roles comprise 28 and
67 disjoint ephemeral sessions from the same model/config, not two human
annotators. Three rejected B batches were rerun after fail-closed validation;
their raw invalid JSON was not retained. All accepted outputs remain
`label_is_human=false` and cannot replace human gold.

### Post-hoc failure-mode diagnostic

The frozen cohort has a separate read-only diagnostic that joins source rows
with non-human strict consensus without changing the production comparator:

```bash
python3 experiments/rq2_discrepancy_typing/test_analyze_rq2_typing_holdout_failure_modes.py
python3 experiments/rq2_discrepancy_typing/analyze_rq2_typing_holdout_failure_modes.py
```

Outputs:

- `results/holdout/rq2_typing_v1/typing_holdout_failure_mode_diagnostic.{json,md}`
- `results/holdout/rq2_typing_v1/typing_holdout_failure_mode_cases.jsonl`

The diagnostic identifies two different mechanisms. First, all 165 strict
severity disagreements occur where the canonical labels match but the frozen
review protocol additionally considers score, vector, and CVSS version; the
current baseline compares labels only. Second, 25 affected_versions rows have
an empty raw side and a package-specific unbounded claim on the other side.
The current span projection drops `introduced=0` with no upper bound, causing
those rows to appear empty on both sides.

A post-hoc construct-aligned profile fits 1,121/1,147 non-human strict rows,
versus 931/1,147 for the current baseline. This is same-cohort diagnostic fit,
not holdout improvement, human accuracy, or a production-switch result. The
result artifact records that boundary explicitly.

### Cross-protocol contract-stability no-go

The same new-contract projection is replayed against the older RQ2 AI-gold
primary and review cohorts before any comparator change is considered:

```bash
python3 experiments/rq2_discrepancy_typing/test_analyze_rq2_typing_contract_stability.py
python3 experiments/rq2_discrepancy_typing/analyze_rq2_typing_contract_stability.py
```

Outputs:

- `results/holdout/rq2_typing_v1/contract_stability/rq2_typing_contract_stability.{json,md}`
- `results/holdout/rq2_typing_v1/contract_stability/rq2_typing_contract_stability_cases.jsonl`

For severity, the new missing-score/vector contract changes correctness by
`-23` rows on the older 60-row primary field slice, `-7` on its 12-row review
slice, and `+165` on the 239-row fresh strict slice. This direction reversal is
a protocol-generation effect, not stable candidate evidence.

Affected_versions is not even label-input comparable. Ten older primary rows
have both range values projected to empty while retaining a GHSA-only package
identity; all ten older non-human labels are equivalent. The fresh holdout
instead supplies raw one-sided unbounded claims and has 25 strict incomplete
labels. The diagnostic does not reconstruct historical raw claims from the
current snapshot or report a synthetic cross-cohort accuracy.

The advancement gate is `no_go_protocol_incompatible`: pooled performance and
production switching are forbidden until a shared calibration set is signed
under one explicit human-approved field contract, all compared inputs preserve
the same raw values, and a new time cohort is sealed after the contract.

### Contract calibration v1 and disjoint v2

The cross-protocol no-go is followed by two sealed, non-human development
calibrations. Neither changes the production comparator or creates human gold.

V1 selects 60 fresh-holdout rows across disputed severity/affected-version
constructs and unchanged controls. Its A/B passes reach 57/60 exact agreement
and strict consensus (kappa 0.9023), but the affected-version unchanged control
reproduces only 6/9 expected labels. The preregistered gate therefore remains
`no_go_ai_calibration_unstable`. The four diagnostic failures separate
cross-CVSS-version comparison, artifact identity, prerelease boundaries, and
singleton-versus-interval subset semantics.

V2 freezes a refined prompt and gate before selecting 42 rows disjoint from all
60 v1 rows. It reaches 42/42 exact agreement, kappa 1.0, and 41/42 strict
coverage. All fixed clauses pass: same-version vector conflicts are 8/8 factual
conflict, cross-version vectors are 6/6 representation discrepancy, repeated
missing-score cases are 5/5 incomplete, and repeated one-sided unbounded claims
are 5/5 incomplete. The full gate still rejects the contract because the
prerelease stratum has only 2/3 strict coverage: both reviewers mark the third
row uncertain because frozen input does not establish a broad XWiki CPE to a
specific Maven component mapping.

An evidence-backed secondary audit then freezes the official GHSA advisory,
fixing commit, and three linked XWiki Jira issues for that one unresolved row.
Both new reviewers cite at least two frozen sources, and both recognize the
`Skin - Skinx` component mapping, but they disagree on the final set relation:
reviewer A remains `uncertain` while reviewer B assigns `incomplete`. Exact and
strict agreement are therefore 0/1, and the augmented gate remains
`no_go_ai_contract_v2_evidence_secondary_unresolved`. This narrows the open
construct from missing web evidence to product-CPE/component-package set
semantics and prerelease mapping; it does not produce a corrected label.

The follow-up artifact-version projection audit makes that abstention
executable. It freezes the XWiki release policy, current Skinx Maven catalog,
three current-lineage POMs, two 3.0 source-path probes, and a legacy Skinx POM.
The current coordinate has 585 catalog entries beginning at
`3.1-milestone-1`; GHSA's `3.0-milestone-1` lower bound and all four explicit
NVD 3.0 releases are absent. The observed predecessor is instead
`com.xpn.xwiki.platform.plugins:xwiki-plugin-skinx:1.13.1`, and no frozen POM
binds it to the current coordinate. An independent verifier therefore enforces
`abstain_artifact_version_projection_unresolved` and a non-human `uncertain`
typing disposition. The audit does not claim the functionality was absent in
3.0; it rejects an unproven cross-lineage version projection.

Projection v2 then freezes the missing historical edges instead of assuming
them. Five XWiki Enterprise 3.0 parent/web POM pairs map product releases to
legacy Skinx `1.20`, `1.21`, and `1.22`; five vulnerability-relevant source
files are byte-identical across the legacy `1.22` to current
`3.1-milestone-1` transition. In the resulting 588-release product domain,
NVD has 412 releases and GHSA 413: NVD is a strict subset, with only
`3.0-milestone-1` missing. The independently verified gate is
`artifact_version_projection_allowed_development_only`, yielding an
`incomplete` development candidate. It remains post-unsealing and non-human;
the sealed reviewer consensus and production gate are unchanged.

A cross-case audit then fixes a generic graph contract before fetching its
case evidence. Its selector reads raw v2 source rows, not reviewer files, and
selects all eight two-sided rows with one subject per source, different full
artifact identifiers, and equal non-empty range signatures. Official boundary
POMs, root `composer.json` files, Go module manifests, and the Moby project
record provide 33 frozen responses across Maven, Packagist, and Go. All eight
fail-closed graph gates pass across `package_identity`,
`product_contains_artifact`, and `artifact_alias` edges. The resulting eight
non-human `representation_discrepancy` development candidates match both
sealed AI reviewers. This is construct coverage on an already unsealed,
non-human-label-conditioned equality stratum, not accuracy or generalization;
the following audits test non-equal claims and both homogeneous and
heterogeneous multi-package cases, while a later untouched time cohort remains
untested.

The next audit keeps that graph contract and its relation-to-taxonomy map
unchanged. It excludes the already analyzed XWiki row and selects all five
remaining two-sided, one-subject, cross-artifact rows whose raw interval
signatures differ. Frozen Maven, Packagist, Jenkins, and npm catalogs bind four
of five projections; Graylog abstains because Maven Central omits the advisory
prerelease boundaries. phpMyFAQ and Pimcore produce strict-subset
`incomplete` candidates that match both sealed AI reviewers. Electron Packager
and Jenkins resolve to equal sets over the frozen released-version catalogs and
therefore produce `representation_discrepancy`, while both reviewers reason
intensionally from singleton-versus-range syntax and assign `incomplete`.
Projection coverage reaches the fixed 4/5 threshold, but agreement with both
sealed AI reviewers is only 2/5, below the fixed 4/5 threshold. The advancement
gate is `no_go_non_equal_graph_unstable`. This does not establish that the AI
or catalog interpretation is correct; it identifies an extensional-versus-
intensional range contract that requires explicit human approval.

To make the assistant's technical choice testable rather than implicit, the
next diagnostic freezes a `codex_expert_contract_candidate` that compares
finite published-release sets at the aligned snapshot. A raw selector that
does not read reviewer labels finds one one-product-to-many-components row,
InLong `CVE-2023-30465`. Maven catalogs and three same-version parent POMs per
component bind `manager-pojo` and `manager-service` to the InLong manager
product. Both component affected sets are `{1.4.0,1.5.0}`; their union equals
the NVD product points, so the technical gate passes `1/1` and yields a
non-human `representation_discrepancy` candidate. Both sealed AI reviewers
assign `incomplete`, leaving consistency at `0/1` and the status
`snapshot_extensional_projection_supported_human_resolution_required`. This
single homogeneous-component case does not override the non-equal no-go or
validate heterogeneous component ranges.

A subsequent selector leaves the reviewed calibration entirely and reads the
full aligned NVD-GHSA input. Without reviewer or consensus files, it takes the
minimum SHA-256-ranked heterogeneous two-package row in each previously
untested ecosystem: Oracle/NuGet, LangChain/PyPI, and Deno/crates.io. Fourteen
official registry, package-metadata, dependency, and vendor responses enumerate
all six component sets. None establishes a deterministic total mapping into
the NVD product domain. Oracle's product tokens and NuGet package versions are
not mapped, LangChain permits a range of numexpr versions, and two Deno product
fix boundaries are absent from the `deno` crate catalog while its
`deno_runtime` dependency is also a caret constraint. All three rows abstain,
so the fixed at-least-2/3 and two-ecosystem gate is
`no_go_unseen_ecosystem_graph_unstable`. This is a label-independent construct
no-go, not reviewer accuracy or evidence that the registries are wrong.

A fixed-before-fetch post-no-go diagnostic then revisits only the Deno row with
an edge class that the parent audit explicitly allowed but did not yet have:
an official build lock. It enumerates all stable official Deno GitHub releases
from `1.41.3` through `2.3.2`, includes immediate predecessor/successor anchors,
and parses the exact `deno_runtime` entry from every tag's committed
`Cargo.lock`. All `71/71` required mappings are exact, catalog-backed, and
monotonic. On the 69-release core domain, the NVD direct set has 63 releases,
while the GHSA direct-plus-runtime union has 68; five fixed-boundary/gap
releases enter only through the runtime claim. The resulting
`nvd_subset_of_ghsa` relation yields a non-human `incomplete` development
candidate. This recovers one product edge; it is not human gold, accuracy, or a
general crates.io rule.

```bash
python3 -m unittest discover \
  -s experiments/rq2_discrepancy_typing -p 'test_*.py'
python3 experiments/rq2_discrepancy_typing/build_rq2_typing_contract_calibration.py
python3 experiments/rq2_discrepancy_typing/merge_rq2_typing_contract_calibration.py
python3 experiments/rq2_discrepancy_typing/analyze_rq2_typing_contract_calibration_failures.py
python3 experiments/rq2_discrepancy_typing/build_rq2_typing_contract_calibration_v2.py
python3 experiments/rq2_discrepancy_typing/merge_rq2_typing_contract_calibration_v2.py
python3 experiments/rq2_discrepancy_typing/build_rq2_typing_contract_evidence_secondary.py
python3 experiments/rq2_discrepancy_typing/merge_rq2_typing_contract_evidence_secondary.py
python3 experiments/rq2_discrepancy_typing/analyze_xwiki_artifact_version_projection.py
python3 experiments/rq2_discrepancy_typing/verify_xwiki_artifact_version_projection.py
python3 experiments/rq2_discrepancy_typing/analyze_xwiki_artifact_version_projection_v2.py
python3 experiments/rq2_discrepancy_typing/verify_xwiki_artifact_version_projection_v2.py
python3 experiments/rq2_discrepancy_typing/build_artifact_lineage_development_cohort.py
python3 experiments/rq2_discrepancy_typing/analyze_artifact_lineage_cross_case.py
python3 experiments/rq2_discrepancy_typing/verify_artifact_lineage_cross_case.py
python3 experiments/rq2_discrepancy_typing/build_artifact_lineage_non_equal_cohort.py
python3 experiments/rq2_discrepancy_typing/analyze_artifact_lineage_non_equal.py
python3 experiments/rq2_discrepancy_typing/verify_artifact_lineage_non_equal.py
python3 experiments/rq2_discrepancy_typing/build_artifact_lineage_multi_component_cohort.py
python3 experiments/rq2_discrepancy_typing/analyze_artifact_lineage_multi_component.py
python3 experiments/rq2_discrepancy_typing/verify_artifact_lineage_multi_component.py
python3 experiments/rq2_discrepancy_typing/build_artifact_lineage_unseen_ecosystem_cohort.py
python3 experiments/rq2_discrepancy_typing/analyze_artifact_lineage_unseen_ecosystem.py
python3 experiments/rq2_discrepancy_typing/verify_artifact_lineage_unseen_ecosystem.py
python3 experiments/rq2_discrepancy_typing/analyze_deno_lockfile_recovery.py
python3 experiments/rq2_discrepancy_typing/verify_deno_lockfile_recovery.py
```

Outputs are under
`data/annotations/holdout/rq2_typing_v1/contract_calibration_v{1,2}/` and
`results/holdout/rq2_typing_v1/contract_calibration_v{1,2}/`; the secondary
packet is nested under v2 as `evidence_secondary_v1/`, with raw API snapshots
under `data/evidence_cache/rq2/typing_contract_evidence_secondary_v1/`.
Builders refuse to overwrite sealed artifacts. Reviewer execution uses the
same strict runner as the full holdout; accepted outputs remain
`label_is_human=false`.

The v2 cross-version shift is evidence that an explicit prompt controls the
construct, not evidence that the new labels are correct. A real-person shared
calibration and author signoff remain required before a human-gold or production
claim.

### Full typing real-human review gate

All 1,250 frozen rows are also projected into a blank, source-bound review
packet. Baseline labels, sampling strata, A/B reviewer outputs, and consensus
labels are omitted. The optional scheduler contains no labels and must remain
author-only.

```bash
python3 experiments/rq2_discrepancy_typing/test_validate_rq2_typing_human_review.py
python3 experiments/rq2_discrepancy_typing/build_rq2_typing_human_review_packet.py
python3 experiments/rq2_discrepancy_typing/validate_rq2_typing_human_review.py
python3 experiments/rq2_discrepancy_typing/validate_rq2_typing_human_review.py --require-signed
python3 experiments/rq2_discrepancy_typing/validate_rq2_typing_human_review.py --require-complete
```

Inputs and outputs:

- `data/annotations/holdout/rq2_typing_v1/human_review/rq2_typing_holdout_human_review.jsonl`
- `data/annotations/holdout/rq2_typing_v1/human_review/author_review_scheduler.jsonl`
- `results/holdout/rq2_typing_v1/human_review/rq2_typing_human_review_readiness.{json,md}`

The current packet has 1,250 pending rows and zero signed rows. Its normal
source/blindness check passes, while `--require-signed` rejects it with exit
code 2. Two different real people must review independently and an author must
sign every row before a separate canonical promotion. Human identity cannot be
proven from an ID string, so it also requires external verification.

### Post-unseal third-pass tiebreak diagnostic

The original A/B merge leaves 103 non-strict rows. A separate builder projects
only those original blind rows into reviewer C's worklist without exposing the
baseline, A/B decisions, consensus, or scheduler. Before C runs, the manifest
fixes a qualified-vote merge rule, a minimum selected-row resolution rate of
0.70, and minimum combined candidate coverage of 0.975. Reviewer C uses the
same frozen prompt and model family in sessions disjoint from A/B, so this is a
post-unseal non-human diagnostic rather than an independent expert or human-gold
review.

```bash
python3 experiments/rq2_discrepancy_typing/build_rq2_typing_tiebreak.py
python3 scripts/run_expert_candidate_annotation.py \
  data/annotations/holdout/rq2_typing_v1/tiebreak_v1/blind/worklist_c.blind.jsonl \
  --task-kind rq2 --rq2-contract-mode strict \
  --pass-id rq2_typing_holdout_v1_tiebreak_c \
  --output-path data/annotations/holdout/rq2_typing_v1/tiebreak_v1/reviewer_c.jsonl \
  --request-log-path data/annotations/holdout/rq2_typing_v1/tiebreak_v1/reviewer_c.requests.jsonl \
  --prompt-path docs/prompts/rq2_typing_holdout_review.md \
  --binding-manifest-path data/annotations/holdout/rq2_typing_v1/tiebreak_v1/manifest.sealed.json \
  --backend codex-cli --model gpt-5.5 --codex-reasoning-effort medium \
  --batch-size 25 --schedule input
python3 experiments/rq2_discrepancy_typing/merge_rq2_typing_tiebreak.py
python3 experiments/rq2_discrepancy_typing/verify_rq2_typing_tiebreak.py
```

The completed C pass covers 103/103 rows. The fixed majority rule resolves
66/103 and yields a combined non-human candidate for 1,213/1,250 rows
(coverage 0.9704), so both advancement thresholds fail and the status is
`no_go_non_human_tiebreak_coverage`. The 37 unresolved rows comprise 28
affected_versions, 6 cwe_ids, 2 references, and 1 severity row. Seventeen are
triple-uncertain and seven still split three qualified votes. This result favors
evidence-enhanced or real-person review over a fourth same-model blind vote.

### Unresolved evidence-secondary D/E audit

The 37 rows still unresolved after reviewer C enter a second post-unseal stage.
Before new URL retrieval, the repository freezes the selector, evidence ranking,
opposite D/E order, strict citation rule, and advancement thresholds. D/E see
the original blind row plus up to six frozen records from URLs already listed by
NVD or GHSA. They do not see A/B/C labels, baseline predictions, vote groups, or
the author-only triage artifact.

```bash
python3 experiments/rq2_discrepancy_typing/build_rq2_typing_unresolved_evidence_secondary.py
# Run scripts/run_expert_candidate_annotation.py for sealed worklist D and E
# with pass IDs rq2_typing_unresolved_evidence_v1_d and ..._v1_e.
python3 experiments/rq2_discrepancy_typing/merge_rq2_typing_unresolved_evidence_secondary.py
python3 experiments/rq2_discrepancy_typing/verify_rq2_typing_unresolved_evidence_secondary.py
```

The frozen evidence snapshot gives 28/37 rows at least one successful non-empty
record. D/E agree exactly on 25/37 labels, but 19 of those are shared uncertain
decisions. Only 6/37 rows satisfy strict consensus and the evidence-citation
gate: 0/28 affected_versions, 4/6 cwe_ids, 1/2 references, and 1/1 severity.
Combined non-human candidate coverage reaches 1,219/1,250 (0.9752), below the
fixed 0.40 secondary-resolution and 0.982 combined-coverage thresholds. The
status is `no_go_non_human_evidence_secondary`. Generic reference-page evidence
does not establish the product/package/range mappings required by the remaining
version rows; it is not a reason to force labels or relax the gate.

### Residual non-affected evidence diagnostic

The two `cwe_ids` rows and one `references` row still unresolved after D/E enter
a disclosed post-unsealing diagnostic. The target is outcome-selected and
protocol discovery inspected the evidence shape before v1, so the 12 official
responses, three-row worklist, source-code/CWE/reference gates, and no-promotion
boundary are sealed for mechanism analysis only.

```bash
python3 experiments/rq2_discrepancy_typing/build_rq2_residual_nonaffected_evidence.py
python3 experiments/rq2_discrepancy_typing/analyze_rq2_residual_nonaffected_evidence.py
python3 experiments/rq2_discrepancy_typing/verify_rq2_residual_nonaffected_evidence.py
```

For `CVE-2024-8020`, the frozen PyTorch Lightning `2.3.2` handler binds
`POST /api/v1/state`, parses the request body, directly indexes
`body["state"]`, and contains no local `try`; this supports CWE-248 and yields a
non-human `factual_conflict` development candidate against NVD's disjoint
CWE-400. `CVE-2023-4304` remains uncertain because official CWE-840 is a
prohibited vulnerability mapping category while the fixing patch adds nonempty
name/email validation without establishing authorization semantics.
`CVE-2023-32187` also remains uncertain: exact frozen HTTP resources yield
`representation_discrepancy`, whereas a narrowly repaired intended Bugzilla
lookup yields `incomplete`. The independent verifier reconstructs all three
routes without importing the analyzer. No candidate is promoted, combined
coverage remains 1,219/1,250 (0.9752), and `label_is_human=false` throughout.

### Staged adjudication frontier and request-provenance audit

The post-hoc frontier audit reads the immutable A-E request logs and sealed
merge summaries without changing labels or backfilling legacy events. Exact
request identity is the ordered `sample_id` payload. Excess requests, retry
row-attempts, successful-response token usage, and each stage's marginal
candidate yield are recomputed by an independent verifier.

```bash
python3 experiments/rq2_discrepancy_typing/analyze_rq2_staged_adjudication_frontier.py
python3 experiments/rq2_discrepancy_typing/verify_rq2_staged_adjudication_frontier.py
```

The logs contain 111 request events and 108 successful responses. Reviewer B
has three excess request attempts covering 90 retry row-items; every affected
row eventually has a successful output, but the missing attempt-level error
reasons cannot be reconstructed and one duplicate-payload attempt is
ambiguous. Across all five roles, 2,767 request row-attempts produce 2,677
successful reviewer-row decisions. Candidate yield falls from 66/103 for C to
6/37 selected rows for D/E, or 6/74 per successful reviewer-row decision. The
final 1,219 rows remain nine short of the fixed 1,228-row target, and the
targeted residual audit promotes zero rows. The frozen decision is therefore
`stop_same_model_escalation_no_go`. Recorded token totals cover successful
responses only; this is an operational frontier, not accuracy, human gold, or
a prediction of real-review yield.

### Unresolved affected-version edge audit and repeated-family graphs

The 28 unresolved affected-version rows are classified from the sealed blind
worklist before D/E diagnostics are loaded. The fixed family rules produce 16
families. Three repeated families pass the structural work-allocation gate:
Mattermost, LF Edge EVE, and Hutool, with fixed scores 14, 9, and 8. Mattermost
is selected because both rows share stable spans, use one ecosystem, and reuse
an already frozen official `mattermost_server` to `server/v8` identity edge.
This ranking is not an expected-success estimate.

```bash
python3 experiments/rq2_discrepancy_typing/analyze_unresolved_affected_edge_classes.py
python3 experiments/rq2_discrepancy_typing/verify_unresolved_affected_edge_classes.py
python3 experiments/rq2_discrepancy_typing/analyze_mattermost_release_graph.py
python3 experiments/rq2_discrepancy_typing/verify_mattermost_release_graph.py
```

Mattermost v1 stops before analysis when the GitHub Releases API reaches its
pagination cap instead of an empty page. V2 also stops before manifests because
`10.3.0` and `10.4.0` are not GitHub Release objects in the frozen prefix. V3
explicitly switches to a fixed 19-token Git-tag manifest domain. All 19 exact
tags bind `server/go.mod` to `github.com/mattermost/mattermost/server/v8`, and
both pseudo-version commits bind exact SHA, committer timestamp, and module
identity. However, the first pseudo commit diverges from all 19 product tags;
the second has 3 `ahead`, 15 `diverged`, and 1 `identical` comparison. The
legacy repository binds no exact tag manifest in the domain. Both rows
therefore abstain, the family gate is `0/2`, and no candidate is added.

The 160 frozen response/metadata files and both independent verifiers preserve
this as `no_go_mattermost_release_graph_unstable`. Product/module identity and
an exact pseudo commit do not establish a total branch/backport or legacy
coordinate mapping. All outputs remain `label_is_human=false`.

The second-ranked LF Edge EVE family is evaluated under a separate v1 contract.
Its disclosed protocol discovery fixes 207 official release tags from `3.0.0`
through `10.1.0`, including the LTS channel, before the graph run. A filtered
Git clone is converted into a 2.67 MB content-addressed pack containing 10,182
reachable commits and 11,070 required commit/tag/tree/blob objects. This avoids
hundreds of compare-API calls. The independent verifier loads that pack into an
empty bare repository, binds every tag to the frozen official refs, and
recomputes all 414 tag-to-pseudo ancestry relations without network access.

```bash
python3 experiments/rq2_discrepancy_typing/analyze_lf_edge_eve_release_graph.py
python3 experiments/rq2_discrepancy_typing/verify_lf_edge_eve_release_graph.py
```

Both pseudo suffixes bind exact commits and UTC committer timestamps, but the
public GitHub advisory API snapshot exposes the historical root coordinate
`github.com/lf-edge/eve` and pseudo version rather than the component paths and
product release anchors shown by the repository advisory UI. The repository has
no root `go.mod` at either pseudo commit. For CVE-2023-43630, the changed path is
inside `pkg/pillar/evetpm` and the owning `pkg/pillar/go.mod` binds its nested
module, yet ancestry is `1 ahead / 17 behind / 189 diverged`. For
CVE-2023-43632, the pseudo commit changes `pkg/xen-tools`, not the advisory's
`pkg/vtpm` component, and ancestry is `3 ahead / 14 behind / 1 identical / 189
diverged`. Both rows therefore abstain and the family gate is `0/2`.

This is `no_go_lf_edge_eve_release_graph_unstable`, not evidence that either
source is correct. Protocol discovery inspected tag and component structure
before v1, so candidate promotion is disabled even if a row had passed. The
combined non-human candidate remains 1,219/1,250 (0.9752), and all EVE outputs
remain `label_is_human=false`.

The third-ranked Hutool family uses a separately frozen Maven snapshot contract.
The three Maven Central catalogs for `hutool-all`, `hutool-core`, and
`hutool-json` contain the same 214 tokens. The fixed stable grammar retains 209
numeric releases and excludes five milestone tokens. Source aggregate POMs and
published aggregate JARs at `5.8.19`, `5.8.21`, and `5.8.22` bind same-version
core/json dependencies and compiled package contents at those critical anchors.

```bash
python3 experiments/rq2_discrepancy_typing/analyze_hutool_maven_release_graph.py
python3 experiments/rq2_discrepancy_typing/verify_hutool_maven_release_graph.py
```

Under the declared snapshot-extensional interpretation, the NVD sets contain
181 and 1 stable releases while both GHSA unions contain all 209 releases. Both
relations are `nvd_subset_of_ghsa`, producing two Codex development
`incomplete` candidates and a 2/2 mechanism gate. Protocol discovery had already
observed catalog equality and anchor structure, however, so candidate promotion
is disabled. The result status is `mechanism_pass_requires_new_blind_cohort`,
the combined candidate stays 1,219/1,250 (0.9752), and every output remains
`label_is_human=false`.

The frozen Hutool mechanism is then applied to a CVE-exposure-disjoint cohort
from the same 8,066-row aligned snapshot. The builder excludes the union of
1,967 CVEs exposed by the prior calibration, holdout, impact, and mechanism
artifacts, and selects six remaining Hutool rows without using baseline,
reviewer, or consensus labels: two direct aggregate routes and four
aggregate-component routes. The cohort is sealed before candidate analysis.
Because its availability and structural shape were observed in the same
snapshot before sealing, this is a retrospective external application rather
than a future time holdout.

```bash
python3 experiments/rq2_discrepancy_typing/build_hutool_maven_external_application.py
python3 experiments/rq2_discrepancy_typing/analyze_hutool_maven_external_application.py
python3 experiments/rq2_discrepancy_typing/verify_hutool_maven_external_application.py
```

All six rows pass the frozen projection gate over the 209-release domain. Five
are NVD strict subsets of GHSA and produce non-human `incomplete` development
candidates; one has equal released-version sets and produces
`representation_discrepancy`. The independent verifier reconstructs the
exclusion union, cohort, and set relations from authoritative inputs. Candidate
promotion remains disabled, the combined candidate remains 1,219/1,250
(0.9752), and every output remains `label_is_human=false`.

## Post-profile paired-test identifiability

The label-free paired-test diagnostic reads only the sealed 250-row source and
six profile-prediction columns. It groups identical prediction vectors,
enumerates all five-label assignments on the representative profile-difference
rows, and computes the conditional exact two-sided McNemar test at alpha 0.05.

```bash
python3 experiments/rq2_discrepancy_typing/analyze_rq2_post_profile_paired_test_identifiability.py
python3 experiments/rq2_discrepancy_typing/verify_rq2_post_profile_paired_test_identifiability.py
```

The six profiles collapse to two prediction vectors with three cross-class
differences. No one of the 125 logical label assignments can reject at alpha
0.05; the minimum attainable p-value is 0.25, and six same-direction
correctness-discordant rows are only the theoretical minimum for any rejection.
The future-cohort and conditional-power values are assumption-bound design
sensitivities, not probabilities over labels, preregistered sample sizes,
human-gold results, or evidence for promotion.

## Post-profile eligible-universe prediction census

The prediction-only census applies the six already frozen profiles to every
field of all 5,948 snapshot-external eligible CVEs. It does not draw another
sample or read any reviewer, evidence-secondary, consensus, or human label.
Before extension, it must exactly replay all six sealed prediction columns on
the original 250-row cohort.

```bash
python3 experiments/rq2_discrepancy_typing/analyze_rq2_post_profile_eligible_universe_prediction_census.py
python3 experiments/rq2_discrepancy_typing/verify_rq2_post_profile_eligible_universe_prediction_census.py
```

Outputs:

- `results/holdout/rq2_post_profile_snapshot_v1/eligible_universe_prediction_census_v1/analysis.json`
- `results/holdout/rq2_post_profile_snapshot_v1/eligible_universe_prediction_census_v1/prediction_difference_rows.jsonl`
- `results/holdout/rq2_post_profile_snapshot_v1/eligible_universe_prediction_census_v1/manifest.json`
- `results/holdout/rq2_post_profile_snapshot_v1/eligible_universe_prediction_census_v1/summary.md`

The replay is exact. Across 29,740 field instances, the union contains 34
prediction-difference rows on 34 unique CVEs and no CVE differs in multiple
fields. Relative to `current`, the original and audited references profiles
differ on 5 and 3 references rows, the CWE profile differs on 29 `cwe_ids`
rows, and the original/audited combined profiles differ on 34 and 32 rows.
Unlike the 250-row sample, all six full-universe prediction vectors are
distinct. This revealed-snapshot census has no correctness labels. It shows
where deterministic profiles differ and invalidates use of 3/250 as a simple
population difference-rate estimate; it cannot establish accuracy, method
gain, temporal generalization, future prevalence, power, or promotion.

## Post-profile strict event-time availability refresh

Repeated acquisition must use a new raw, processed, and result directory. It
must not overwrite the sealed snapshot-external cohort or use any reviewer
output. For a future v3 refresh, run:

```bash
python3 experiments/rq2_discrepancy_typing/build_rq2_post_profile_snapshot.py \
  --raw-dir data/raw/time_cohort/rq2_post_profile_snapshot_v3 \
  --processed-dir data/processed/time_cohort/rq2_post_profile_snapshot_v3 \
  --result-dir results/holdout/rq2_post_profile_snapshot_v3/acquisition
python3 experiments/rq2_discrepancy_typing/verify_rq2_post_profile_snapshot.py \
  --manifest results/holdout/rq2_post_profile_snapshot_v3/acquisition/manifest.json
python3 experiments/rq2_discrepancy_typing/analyze_rq2_post_profile_acquisition_delta.py \
  --previous-manifest results/holdout/rq2_post_profile_snapshot_v2/acquisition/manifest.json \
  --current-manifest results/holdout/rq2_post_profile_snapshot_v3/acquisition/manifest.json \
  --output-dir results/holdout/rq2_post_profile_snapshot_v3/acquisition_delta_v2_to_v3
python3 experiments/rq2_discrepancy_typing/verify_rq2_post_profile_acquisition_delta.py \
  --manifest results/holdout/rq2_post_profile_snapshot_v3/acquisition_delta_v2_to_v3/manifest.json
```

The v1-to-v2 delta finds 39 NVD records published after the profile freeze but
zero reviewed GHSA records published after it. The one-GHSA matched set remains
5,948 and the field views are byte-identical, so strict event-time eligibility
remains zero. A new cohort must not be frozen until the independently verified
strict count reaches the predeclared minimum of 25 unique CVEs. Acquisition
delta outputs contain no labels and cannot establish temporal validation,
accuracy, human gold, or future-snapshot generalization.

## AI-adjudicated gold diagnostic

The separate AI-gold pipeline re-reviewed `53/300` risk rows and retained `18`
uncertain rows. On the remaining `282` rows, the current baseline has accuracy
`0.8972` and macro-F1 `0.9084`; the combined reference/CWE candidate has
`0.9326` and `0.9323`. Same-model consistency is `50/60` with kappa `0.7923`.

Run:

```bash
python3 experiments/ai_adjudicated_gold/evaluate_rq2_ai_gold.py
```

The output is a selection-aware, same-model-family diagnostic. It is not
human-gold performance, does not change production defaults, and is not eligible
for a final paper claim.
