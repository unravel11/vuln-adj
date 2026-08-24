# RQ2 Typing Human Review Packet

This directory contains a blank, source-bound review packet for all 1,250 frozen RQ2 holdout rows. No baseline label, sampling stratum, non-human reviewer label, or consensus label appears in the review rows.

## Required process

1. A real human annotator labels every row from `rq2_typing_holdout_human_review.jsonl`.
2. A different real human repeats the review independently without seeing the first decision.
3. An author records the final resolution and signs each row.
4. Run the fail-closed validator with `--require-complete` before any separate canonical promotion.

`author_review_scheduler.jsonl` is optional author-only workflow metadata. It prioritizes unresolved non-human rows but contains no labels; do not expose it to annotators. The JSONL packet is authoritative. Human identity and independence must also be verified outside the file because a validator cannot prove that an ID belongs to a real person.
