# AI-Adjudicated Gold Diagnostics

This directory builds and evaluates provenance-preserving AI-adjudicated gold.
These artifacts are not human-gold and are not eligible for final paper claims.

## Build snapshots

Run on the authoritative remote host:

```bash
python3 experiments/ai_adjudicated_gold/build_ai_adjudicated_gold.py \
  --dataset rq2_primary \
  --adjudication-input data/annotations/ai_adjudicated_gold/adjudication_passes/rq2_primary.jsonl \
  --required-worklist results/ai_adjudicated_gold/worklists/rq2_primary_risk.jsonl
python3 experiments/ai_adjudicated_gold/build_ai_adjudicated_gold.py --dataset rq2_review
python3 experiments/ai_adjudicated_gold/build_ai_adjudicated_gold.py \
  --dataset rq3_severity \
  --adjudication-input data/annotations/ai_adjudicated_gold/adjudication_passes/rq3_severity.jsonl \
  --required-worklist results/ai_adjudicated_gold/worklists/rq3_severity_risk.jsonl
python3 experiments/ai_adjudicated_gold/build_ai_adjudicated_gold.py \
  --dataset rq3_affected_versions \
  --adjudication-input data/annotations/ai_adjudicated_gold/adjudication_passes/rq3_affected_versions.jsonl \
  --required-worklist results/ai_adjudicated_gold/worklists/rq3_affected_versions_risk.jsonl
```

The builder rejects human provenance claims and requires exact coverage of every
selected risk row. Uncertain labels and RQ3 source abstentions remain
`final_abstain`; they are not silently dropped.

## Evaluate

```bash
python3 experiments/ai_adjudicated_gold/evaluate_rq2_ai_gold.py
python3 experiments/ai_adjudicated_gold/evaluate_rq3_ai_gold.py
```

Outputs:

- `results/ai_adjudicated_gold/rq2/rq2_ai_gold_metrics.{json,md}`
- `results/ai_adjudicated_gold/rq3/rq3_ai_gold_metrics.{json,md}`

Current diagnostic coverage is RQ2 `282/300`, RQ3 severity `79/80`, and RQ3
affected_versions `40/100`. Metrics exclude `final_abstain` rows and always
report the resulting gold coverage. Production defaults remain unchanged.

The affected_versions snapshot was rebuilt after the 2026-07-15
`vulnerable=false` input repair. Seven frozen sample rows had refreshed source
inputs and received targeted AI-provenance recheck notes, but no final label or
source decision changed. The snapshot remains `label_is_human=false`; the input
repair does not convert it into human-gold.

## Paired uncertainty and affected-version ceiling

Run the descriptive paired bootstrap and exact paired diagnostics, followed by
the structured affected-version bottleneck analysis:

```bash
python3 experiments/ai_adjudicated_gold/analyze_ai_gold_uncertainty.py
python3 experiments/ai_adjudicated_gold/analyze_package_identity_crosswalk.py
python3 experiments/ai_adjudicated_gold/analyze_affected_versions_ai_gold_ceiling.py
```

Outputs:

- `results/ai_adjudicated_gold/uncertainty/ai_gold_paired_uncertainty.{json,md}`
- `results/ai_adjudicated_gold/package_identity_crosswalk/package_identity_crosswalk_diagnostic.{json,md}`
- `results/ai_adjudicated_gold/affected_versions_ceiling/affected_versions_ai_gold_ceiling.{json,md}`

The default uncertainty run uses `10,000` stratified paired percentile
bootstrap replicates with seed `20260715`. The affected-version analysis uses
the structured `version_reasoning_type` field, package/range diagnostics, and a
post-hoc tested-method union oracle; it does not infer causes from rationale
free text. The crosswalk uses only source package names and source reference
URLs, rejects generic and conflicting repository bridges, and joins AI-gold
only for evaluation. The oracle is not deployable, final-abstain rows have no
accuracy target, and none of these artifacts supports population or final-paper
claims.

## Release-boundary exploratory diagnostic

```bash
python3 experiments/rq3_adjudication/extract_affected_versions_release_boundaries.py
python3 experiments/ai_adjudicated_gold/evaluate_affected_versions_release_boundaries.py
```

The extractor emits 100 gold-blind feature rows before the evaluator joins
AI-gold. After sentence-local cue-binding corrections, the boundary method is
`22/40` at `0.95` coverage and the fixed boundary-then-crosswalk-canonical
composition is `23/40`. Against unrestricted canonical token, the paired delta
is `+7.5pp` with interval `[-12.5,+27.5]pp`, 14 improvements, 11 regressions,
and exact p=`0.6900`. The feature adds 11 previously missed rows to the post-hoc
method union, but this was selected after inspecting prior misses and is not a
deployable selector or human-gold result.

## Branch/release-graph exploratory diagnostic

```bash
python3 experiments/rq3_adjudication/test_affected_versions_branch_graph.py
python3 experiments/rq3_adjudication/extract_affected_versions_branch_graph.py
python3 experiments/ai_adjudicated_gold/evaluate_affected_versions_branch_graph.py
```

Outputs:

- `results/rq3_adjudication/branch_graph/affected_versions_branch_graph_features.jsonl`
- `results/rq3_adjudication/branch_graph/affected_versions_branch_graph_features_summary.json`
- `results/ai_adjudicated_gold/branch_graph/affected_versions_branch_graph_ai_gold_diagnostic.{json,md}`

The gold-blind candidate adds conservative structural events for opaque ordinal
exceptions, adjacent prerelease boundaries, and explicit affected endpoints
versus open-ended spans. It changes only `4/100` predictions. On the 40
determinate AI rows, the standalone candidate is `25/40` at `0.975` coverage
and the fixed fallback is `26/40`. Relative to the release-boundary fallback it
has 3 improvements and no regressions, a `[0,+15]pp` percentile interval, and
exact p=`0.25`. The post-hoc tested-method union reaches `37/40`, but source
authority, temporal revision, multi-branch snapshot repair, backports, and
ecosystem-specific ordering remain unresolved. The representation was designed
after residual inspection, so these remain exploratory, non-human results.

## Affected-version strict source re-audit

Build the 45-row re-audit selection, compare the isolated evidence refresh,
validate the two Codex decision files, and evaluate the source overlay:

```bash
python3 experiments/ai_adjudicated_gold/build_affected_versions_source_reaudit_inputs.py
python3 experiments/ai_adjudicated_gold/analyze_source_reaudit_evidence_refresh.py
python3 experiments/ai_adjudicated_gold/test_merge_affected_versions_source_reaudit.py
python3 experiments/ai_adjudicated_gold/merge_affected_versions_source_reaudit.py
python3 experiments/ai_adjudicated_gold/evaluate_affected_versions_source_overlay.py
python3 experiments/ai_adjudicated_gold/analyze_source_overlay_branch_failures.py
```

The isolated refresh covers 234 URLs. Usable records increase from 157 to 214;
26/45 selected rows gain evidence and none lose evidence. Two Codex reviewers
then independently apply a strict source contract: missing evidence cannot
exclude a source, and unilateral labels require affirmative contradiction or
scope exclusion. They agree on 36/45 source labels (kappa `0.3982` including
abstain), but only four exact non-abstain agreements pass the confidence gate.
All four are `both`, so the source overlay expands from `40/100` to `44/100`.

On the four added rows, canonical token is `4/4`; release-boundary and branch
graph are both `0/4`. On the combined 44 rows, branch-graph with fixed fallback
is `26/44=0.5909`, versus canonical token `24/44=0.5455`; the paired delta is
`+4.55pp` with interval `[-13.64,+22.73]pp` and exact p=`0.8601`. This weakens
the earlier 40-row result and exposes cross-artifact boundary conflicts: all
four added cases use different product/package version spaces. The required
next capability is evidence-bound artifact identity with separate release
graphs, not another version-token exception.

Outputs:

- `results/ai_adjudicated_gold/source_reaudit/affected_versions_source_reaudit_consensus_summary.json`
- `results/ai_adjudicated_gold/source_reaudit/rq3_affected_versions_source_gold_overlay.jsonl`
- `results/ai_adjudicated_gold/source_reaudit/affected_versions_source_overlay_diagnostic.{json,md}`
- `results/ai_adjudicated_gold/source_reaudit/affected_versions_source_overlay_branch_failures.{json,md}`

Both reviewers are Codex agents, not human annotators. The overlay is selected
from prior uncertain rows. This 44-row mixed-contract result is retained as a
historical diagnostic; the original 40 rows have now been rerun under the same
strict contract, as described below. No production default changes.

## Uniform strict source overlay and artifact-bound v2

The original 40 determinate rows were refreshed and independently re-audited by
two new Codex agents under the same source contract. Exact agreement is `29/40`
with kappa `0.6502`; 27 exact non-abstain, non-low-confidence rows are accepted.
Together with the four strict prior-abstain additions, the uniform overlay has
`31/100` determinate source labels. Two accepted original labels change source:
sample `029` from `both` to `nvd`, and sample `092` from `nvd` to `ghsa`.

Agent A's first output failed the schema because one field used lists and was
fixed by a format-only resumed pass. Agent B disclosed that the first full
candidate object was visible during schema inspection; it stated that prior
source was not used as evidence, but perfect blinding is not claimed. All rows
remain `label_is_human=false`.

Artifact-bound v2 requires source-exclusive package aliases, a CVE-scoped
same-record artifact match, and positive version-token support on both sides.
It only changes branch predictions of `abstain` or `neither` to `both`; it does
not override one-sided decisions. Run the deterministic checks and final
same-input benchmark with:

```bash
python3 experiments/rq3_adjudication/test_affected_versions_artifact_graph.py
python3 experiments/ai_adjudicated_gold/analyze_artifact_graph_evidence_snapshot_stability.py
python3 experiments/ai_adjudicated_gold/analyze_artifact_graph_uniform_strict_failures.py
python3 experiments/ai_adjudicated_gold/evaluate_affected_versions_uniform_strict_methods.py
```

On the selection-aware uniform evidence input, the full-coverage ranking starts
with raw token `18/31=0.5806`, canonical token `17/31=0.5484`, and artifact v2
`16/31=0.5161`; branch graph is `12/31=0.3871`. The best selective result is a
tie between package-range and package-gated token at `12/19=0.6316`, with
prediction coverage `19/31=0.6129`. Artifact v2 repairs all four strict
prior-abstain additions but does not beat the simpler baselines overall.

Evidence refresh changes branch raw predictions on `15/100` rows. On the legacy
44-row cohort, branch fallback drops from 26 to 19 correct and artifact fallback
drops from 30 to 23. The current evidence therefore supports artifact identity
and evidence-snapshot sensitivity as threats, not a graph-method improvement or
generalization claim.

Outputs:

- `results/ai_adjudicated_gold/source_reaudit/determinate_reaudit/`
- `results/ai_adjudicated_gold/source_reaudit/uniform_strict/`
- `results/ai_adjudicated_gold/artifact_graph_snapshot_stability/`
- `results/ai_adjudicated_gold/artifact_graph_uniform_strict/`
- `results/ai_adjudicated_gold/artifact_graph_uniform_strict_same_evidence/`

The overlay and evidence refresh are conditioned on prior AI-gold status, and
artifact v2 was designed after failure inspection. They are neither human-gold
nor independent holdout results.

## Development-disjoint follow-up

The current external method diagnostic is the CVE-disjoint
`affected_versions_v1` holdout documented in `experiments/holdout/README.md`.
Its predictions were sealed before dual-Codex review. Strict joint consensus is
35/100, with discrepancy/source kappa 0.2679/0.3919. All-strict fixed graph
fallback is 17/35, but a post-unseal task split shows only 16 strict factual
conflicts; on those rows graph methods are 7/16, tied with prefer-GHSA and
recency. Raw/canonical token are 1/16. This supersedes the old 31-row development
overlay for generalization diagnosis, while remaining non-human and too small
for a confirmatory method claim.
