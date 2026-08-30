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

Current status: protocol frozen; no pilot result has been generated.

