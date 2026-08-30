# Temporal Provenance Qualification Pilot

This directory implements the frozen protocol in
`docs/plans/temporal_provenance_pilot_v1.md`.

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

Current status: protocol, source pins, and the deterministic E0 sample are
sealed. The official current NVD response is acquired. Historical Git states,
the current replay gate, and downstream outcomes are not scientific results
until their corresponding validators pass.

The E0 execution order is fail-closed:

1. `materialize_e0_git_states.py` writes projections plus content-addressed
   raw record blobs from the pinned commits;
2. `verify_e0_git_states.py` independently reparses every available snapshot
   for 20 outcome-independent CVEs and checks the raw digests and loss-sensitive
   structural projections; and
3. `analyze_e0_replay.py` opens historical transition summaries only when both
   the current-state gate and independent-parser verification pass.

The independent parser is a mechanical structural check, not semantic truth.

Pre-acquisition errata that govern historical alignment, NVD affected lineage,
and the stricter E0 replay gate are recorded in
`docs/plans/temporal_provenance_pilot_v1_pre_acquisition_errata_1.md`.
