# Reference Normalization Human Review Packet

This is a blank three-stage packet for all 56 sealed reference-normalization impact rows. The 24 encoded-line rows are `definition_sensitive`; the other 32 rows remain in the packet for full-impact confirmation.

## Required process

1. A real human annotator chooses an identity definition and labels every identity group.
2. A different real human repeats the review independently.
3. An author resolves any difference, records the final identity definition and group decisions, and signs the row.

The permitted definitions and verdict-to-status mapping are recorded in `manifest.json`; they are validator-enforced rather than hidden. Codex outputs are not copied into any human field. The packet remains `label_is_human=false`; canonical promotion is a separate guarded step.

Edit the JSONL file as the authoritative review record. The CSV is a read-only convenience view and is not imported by the validator.
