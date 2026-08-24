# AI-Adjudicated Gold Annotations

This directory contains AI-generated adjudication artifacts with explicit
provenance. Every wrapper has:

- `label_is_human=false`
- `eligible_for_human_gold_claim=false`
- `requires_human_signoff=true`
- `independent_human_review=false`

Layout:

- `interactive_decisions/`: exact risk-worklist override ledgers produced by the
  current interactive Codex review.
- `adjudication_passes/`: validated second-pass wrappers with worklist and
  decision hashes.
- `source_reaudit/`: isolated affected-version evidence refresh and two-agent
  strict source-support re-audit. Its accepted consensus remains non-human and
  is emitted as a separate overlay rather than rewriting the base snapshot.
- `rq2_primary.jsonl`: 300-row primary RQ2 AI-gold snapshot.
- `rq2_review.jsonl`: 60-row same-model consistency snapshot.
- `rq3_severity.jsonl`: 80-row severity AI-gold snapshot.
- `rq3_affected_versions.jsonl`: 100-row affected-version AI-gold snapshot.

Rows marked `final_abstain` preserve unresolved evidence, package identity, or
range semantics. These files must not be copied into `human_audit`, used to fill
human annotator/reviewer fields, or described as human-gold.

The source re-audit also keeps discrepancy typing separate from source support.
Among 45 prior uncertain rows with non-abstain source values, strict dual-agent
review accepts only 4 `both` rows. The resulting 44/100 source overlay is an
AI-provenance diagnostic and does not change the 40/100 base AI-gold snapshot.
