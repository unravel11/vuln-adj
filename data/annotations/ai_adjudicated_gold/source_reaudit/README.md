# Affected-Version Source Re-Audit

This directory contains an isolated, non-human source-support re-audit for RQ3
`affected_versions`. It does not modify the frozen 100-row evidence artifact or
the existing AI-gold snapshot.

Two selections are retained:

- 45 rows with prior `ai_gold_status=final_abstain` and a non-`abstain`
  `adjudicated_source`, recorded in
  `rq3_affected_versions/selection_manifest.json`.
- The original 40 `final_determinate` rows, recorded in
  `rq3_affected_versions_determinate/selection_manifest.json`.

Evidence refresh:

- For the 45-row selection, 234 URLs were fetched into a dedicated cache on the
  authoritative remote. Usable records increased from 157 to 214; 26/45 rows
  gained usable evidence and no row lost usable evidence.
- For the original 40 rows, 234 URLs were refreshed separately. Usable records
  increased from 160 to 224; 20/40 rows gained usable evidence and one row lost
  one usable record.
- Refreshed inputs are under each selection's `evidence_refresh/` directory.
- `rq3_affected_versions/evidence_overlay_uniform/` combines the two refreshed
  selections with 15 frozen rows. Its manifest records that selection was
  conditioned on prior AI-gold status.

Review:

- Each selection has `agent_a_decisions.jsonl` for evidence-first Codex review
  and `agent_b_decisions.jsonl` for skeptical Codex review.
- Every decision row has `label_is_human=false`.
- The agents did not read each other's output and did not call an external LLM.
- A one-sided source label required positive support for the chosen source and
  positive contradiction or scope exclusion for the other source. Missing or
  failed evidence was not accepted as contradiction.
- Agent A's original 40-row file was rejected because one schema field used a
  list instead of a string; the resumed agent made a format-only conversion.
- Agent B disclosed that the first full candidate object was visible during
  schema inspection. It stated that prior source was not used as evidence, but
  perfect blinding is not claimed.

Validated consensus artifacts are written to
`results/ai_adjudicated_gold/source_reaudit/`. Only exact non-abstain agreement
with no low-confidence decision is accepted:

- The 45-row prior-abstain review has 36/45 exact agreement, kappa 0.3982, and
  adds four `both` rows.
- The original 40-row review has 29/40 exact agreement, kappa 0.6502, and
  accepts 27 rows. Two accepted labels differ from the prior source decision.
- The uniform strict overlay combines those 27 rows with the four additions,
  yielding 31/100 determinate source labels and 69 explicit abstentions.

The historical 44-row mixed-contract overlay remains available for audit, but
it is not the current uniform benchmark.

All artifacts remain AI-provenance diagnostics:

- `label_is_human=false`
- `eligible_for_human_gold_claim=false`
- `requires_human_signoff=true`

They must not be copied into human annotator/reviewer fields or reported as
human-gold.
