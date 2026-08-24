# RQ2 Post-Profile Time Cohort Contract v1

## Objective

Collect a new, isolated NVD-GHSA snapshot after the RQ2 profile/holdout seal and
measure whether a genuinely post-profile validation cohort is available before
requesting any Codex labels. The acquisition never overwrites the existing
bootstrap corpus.

The frozen profile boundary is the existing holdout seal timestamp:

`2026-07-18T17:22:22.399430+00:00`

## Official acquisition inputs

- NVD CVE 2.0 2026 feed:
  `https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2026.json.zip`
- GHSA reviewed advisory database: resolve `refs/heads/main` from
  `https://github.com/github/advisory-database.git`, then download the codeload
  archive for that exact commit SHA.
- Existing aligned CVE universe:
  `data/processed/bootstrap/aligned/nvd_ghsa_by_cve.jsonl`
- Existing RQ2 seal:
  `data/annotations/holdout/rq2_typing_v1/manifest.sealed.json`

Only `advisories/github-reviewed` GHSA records are normalized. Unreviewed GHSA
records remain excluded. HTTP headers, source archives, normalized outputs,
and hashes must be retained.

## Eligibility tiers

All tiers require exactly one aligned reviewed GHSA record and a CVE absent
from the existing aligned CVE universe.

### Strict event-time tier

A CVE is strict-event-time eligible only when both normalized NVD and GHSA
`published` timestamps are strictly later than the frozen profile timestamp.
This is the only tier eligible for a post-profile event-time claim.

### Snapshot-external tier

A CVE is snapshot-external eligible when its identifier begins `CVE-2026-` and
it is absent from the existing aligned CVE universe. Records that predate the
profile timestamp remain useful for a newly collected snapshot-development
cohort but cannot support event-time generalization.

## Availability-adaptive size rule

The size rule uses only eligible-row counts, never discrepancy labels or Codex
outputs:

- at least 250 unique CVEs: 50 rows per field;
- 100-249 unique CVEs: 20 rows per field;
- 25-99 unique CVEs: 5 rows per field;
- fewer than 25 unique CVEs: no labeling cohort.

The strict tier is assessed first. If it is unavailable, the snapshot-external
tier may proceed as a separately named development cohort under the same size
rule. No result may silently change tiers after labels are observed.

## Acquisition outputs

The acquisition stage produces source archives, normalized NVD/GHSA records,
aligned rows, current-baseline field views, availability counts, and a
hash-bound manifest. It contains no annotation request, Codex output, candidate
label, or human label.

The subsequent cohort builder, if a tier is available, must seal source rows,
current and already-frozen candidate-profile predictions, blind worklists, and
all input hashes before any reviewer output exists.

## Boundary

- `collection_after_profile_seal=true`
- `selection_uses_labels=false`
- `contains_annotations=false`
- `label_is_human=false`
- `eligible_for_human_gold_claim=false`
- `strict_event_time_claim_requires_strict_tier=true`
- `snapshot_external_is_time_confirmatory=false`
- `production_switch_allowed=false`

Codex may provide expert-candidate annotations in a later stage, but those
annotations remain non-human. Real human-gold still requires two real people
and author signoff under the existing review packet contract.
