# Expert Candidate Human Review Packets

These packets are an isolated handoff from AI security-expert candidates to human review. They are not canonical gold files.

Each row contains the original NVD/GHSA field context, the non-human candidate decision, and a blank `human_review` object. The candidate is evidence for review, not the answer to copy.

## Sign-Off Contract

A row is eligible for later human-gold promotion only when all of these conditions hold:

- `review_status` is `approved` or `revised`.
- `author_signoff` is `signed`.
- `final_label` and `final_rationale` contain the human judgment.
- `human_annotator_id` and `independent_reviewer_id` are non-empty and different.
- `reviewed_at` is an ISO date/time.
- RQ3 non-abstain decisions include evidence URLs and evidence notes.

Run the readiness gate after editing JSONL packets:

```bash
python3 experiments/expert_candidate_validation/validate_human_review_packets.py
```

CSV files are review aids. The JSONL packets are the validated source of truth; CSV edits are not imported automatically.

Do not rename or copy an unsigned packet into `data/annotations/rq2/` or `data/annotations/rq3/gold_audit/`.
