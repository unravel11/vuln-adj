# Temporal Provenance Qualification Pilot

This directory implements the frozen protocol in
`docs/plans/temporal_provenance_pilot_v1.md`.

GHSA merged-PR enumeration and proposal-to-main mapping follow the pre-outcome
workflow addendum in
`docs/plans/temporal_provenance_ghsa_event_discovery_v1.md`. In particular, a
merged PR is an accepted-disposition object, not the provider's final field
state. Direct Git binding, staging-workflow binding, exact delta adoption,
partial delta overlap, already-present values, and unlinked same-field events
remain separate. Only route-bound, stable, exact deltas enter the primary
cohort.

The pilot is isolated from the existing RQ2 routing and JSS paper pipeline.
Existing normalized affected/reference values may define an ID universe, but
they are not reused as historical field truth.

Planned tracked artifacts:

- deterministic E0 sample builder and sealed 100-CVE manifest;
- Git/API raw-state materializers with source commit/event provenance;
- source-specific full-fidelity affected/reference projections;
- accepted-correction event builder;
- offline SCA and known-VFC downstream adapters;
- analysis and an independent verifier; and
- focused unit tests with synthetic fixtures only.

Large repositories, raw snapshots, URL responses, processed rows, and result
payloads remain under ignored `data/` and `results/` paths on the authoritative
remote. Small frozen controls and schemas may be tracked.

Current status: E0 replay passed its engineering gate, and the GHSA discovery
and main-state mapping method is frozen. Full accepted-event denominators and
both downstream outcomes remain unknown until their corresponding acquisition,
mapping, and validators pass.

The E0 execution order is fail-closed:

1. `materialize_e0_git_states.py` writes projections plus content-addressed
   raw record blobs from the pinned commits;
2. `verify_e0_git_states.py` independently reparses every available snapshot
   for 20 outcome-independent CVEs and checks the raw digests and loss-sensitive
   structural projections; and
3. `analyze_e0_replay.py` opens historical transition summaries only when both
   the current-state gate and independent-parser verification pass.

The independent parser is a mechanical structural check, not semantic truth.

The first E1 operation constructs only a reconciled endpoint-visible PR set:

```bash
python3 experiments/temporal_provenance/acquire_ghsa_merged_pr_manifest.py
```

It reconciles two monthly Search traversals with an ordinary closed-pulls REST
traversal before any PR field diff is opened. It does not claim an exhaustive
public PR census because all three traversals share GitHub's visibility and
service boundary. Raw bodies, selected response
headers, and every failed attempt are append-only under the ignored raw-data
tree. Exit code `3` means a public API rate limit paused the run; rerunning the
same command resumes only requests whose successful body and request identity
already match. This stage does not count affected/reference changes.

After acquisition reports
`reconciliation_complete_pending_independent_verification`, independently
rebuild it from the raw
success pointers, response bodies, and attempt ledger before opening field
diffs:

```bash
python3 experiments/temporal_provenance/verify_ghsa_merged_pr_manifest.py
```

The verifier reparses both Search passes and the ordinary Pulls pages, checks
the retained-body digests, and requires exact PR-number and `merged_at`
identity. Its PASS is a mechanical reconciliation check, not proof of
exhaustive history, a correction label, or truth.
Acquisition always writes `downstream_eligible=false`. Only the verifier output
with `status=pass`, `downstream_eligible=true`, the same `run_id`, and a SHA-256
that matches the current manifest bytes may authorize a later field-diff step.
Changing or replacing the manifest invalidates that verifier artifact.

Pre-acquisition errata that govern historical alignment, NVD affected lineage,
and the stricter E0 replay gate are recorded in
`docs/plans/temporal_provenance_pilot_v1_pre_acquisition_errata_1.md`.
