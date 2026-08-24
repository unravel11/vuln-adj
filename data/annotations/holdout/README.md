# Holdout Annotations

`affected_versions_v1/` is a frozen 100-row affected_versions cohort selected
from the 551 current factual-conflict rows that do not overlap the 100-row Phase
D development sample by CVE.

The selection uses a fixed SHA-256 rank and does not read AI-gold, candidates,
method predictions, or error analysis. The reviewer worklist is an allowlisted
view that omits baseline metadata. Evidence uses a dedicated URL cache and all
method predictions are sealed before reviewer decisions.

Codex reviewer decisions and strict consensus are expert-adjudicated candidates,
not human annotations. They must retain `label_is_human=false` and cannot be
copied into the guarded human-audit schema without real annotator, independent
reviewer, and author signoff.

Current v1 evidence covers 568 URL records, including 538 usable text records;
all 100 rows have usable evidence. Dual-Codex strict joint consensus retains
35/100 rows. Reviewer discrepancy/source kappa is 0.2679/0.3919. These values
measure non-human candidate reliability, not human agreement.
