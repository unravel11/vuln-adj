# RQ2 Post-profile Human Review Packet

This directory contains a blank, source-bound packet for all 250 sealed post-profile rows (50 per field). The review rows omit baselines, profile predictions, all non-human reviewer decisions, consensus labels, sampling strata, and author-side priority signals.

## Required process

1. A real human annotator labels every row from `rq2_post_profile_human_review.jsonl`.
2. A different real human repeats the review independently.
3. An author resolves and signs every row.
4. Run the fail-closed validator with `--require-complete`.
5. Verify reviewer identities and independence outside the JSON files before any human-gold claim.

`author_review_scheduler.jsonl` is author-only and contains priority signals but no labels. Do not expose it to either reviewer. The validator checks file integrity and process fields; it cannot prove that an ID belongs to a real person.
