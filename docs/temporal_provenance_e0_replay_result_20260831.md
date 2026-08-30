# Temporal Provenance E0 Replay Result

**Executed**: 2026-08-31  
**Status**: `E0_REPLAY_PASS`  
**Authority**: `code-defender:/home/xiaoyuliang/code/vuln-adj`  
**Branch / execution HEAD**: `codex/temporal-provenance-pilot-20260831` /
`dd13130`  
**Protocol**: `docs/plans/temporal_provenance_pilot_v1.md`

## 1. Plain-language result

The frozen 100-CVE sample can be reconstructed from the three pinned Git
histories at the three fixed checkpoints and at the frozen current commits.
The current NVD projection reproduced from the FKIE historical mirror agrees
with the separately acquired official NVD API response for all 100 CPE and
reference projections. A second parser independently checked 20 deterministic
CVEs across every available source/checkpoint state and found no structural or
raw-digest failure.

This is an engineering replay result. It permits accepted-correction discovery
to begin. It does not establish that an old or new value is factually correct,
that an observed change is a correction, or that the candidate paper direction
has passed its contribution gates.

## 2. Frozen inputs and materialized outputs

- E0 eligibility universe: 2,635 current aligned IDs.
- E0 sample: 100 CVEs selected before historical outcomes by the sealed hash
  rule in `experiments/temporal_provenance/e0_sample_v1.json`.
- Source pins:
  - GHSA: `b695d547ec7cbc0be623463706ee0ac6c3290c92`
  - CVE List: `6c762782de01db8b11c40cc857ea97e0158aa7cb`
  - FKIE NVD mirror: `499fa5d653e13dcc01000d0b4216ccbf6201110b`
- Fixed checkpoints: `2024-01-01T00:00:00Z`,
  `2025-01-01T00:00:00Z`, and `2026-05-31T00:00:00Z`.
- Official current NVD acquisition: 100 requested, 100 returned.
- Git-state output: 1,200 source/checkpoint rows and 751 unique
  content-addressed raw record blobs; the processed E0 directory is 7.6 MiB.

The one-time full CVE List transport clone completed at upstream HEAD
`269bfaa5223169f8435d7ee01fa1c63cf4291767`, later than the sealed source pin.
All reads nevertheless use the sealed commit IDs, and all four required commit
objects per source were verified present. The transport HEAD is provenance,
not the materialized state identity.

## 3. Current replay gate

| Check | Result | Frozen gate | Status |
|---|---:|---:|---:|
| GHSA current record presence | 100/100 | 100/100 | PASS |
| CVE List current record presence | 100/100 | 100/100 | PASS |
| FKIE NVD mirror current presence | 100/100 | 100/100 | PASS |
| Official NVD vs mirror CPE semantics | 100/100 | 100/100 | PASS |
| Official NVD vs mirror reference semantics | 100/100 | 100/100 | PASS |
| Official NVD vs mirror exact projection | 100/100 | audit | observed |
| Independent raw/structure reparse | 240 present states, 0 failures | 20 fixed CVEs | PASS |

The independent audit covers 20 CVEs × 3 sources × 4 states. It compares exact
raw digests and loss-sensitive affected/reference structures. It is not an
independent vulnerability or version truth oracle.

## 4. Observable historical states

### 4.1 State availability

| Source | 2024-01-01 | 2025-01-01 | 2026-05-31 | Current |
|---|---:|---:|---:|---:|
| GHSA current-selected paths | 97 present / 3 absent | 98 / 2 | 100 / 0 | 100 / 0 |
| CVE List | 100 / 0 | 100 / 0 | 100 / 0 | 100 / 0 |
| FKIE NVD mirror | 100 / 0 | 100 / 0 | 100 / 0 | 100 / 0 |

Every present GHSA record contained the selected CVE alias at the corresponding
checkpoint: 97/97, 98/98, 100/100, and 100/100. The early path absence shows
why a current CVE--GHSA mapping cannot simply be carried backward. These are
availability denominators, not database-accuracy rates.

### 4.2 Raw field transitions

| Source | Interval | Both present | Affected changed | References changed | New NVD top-level affected changed |
|---|---|---:|---:|---:|---:|
| GHSA | 2024→2025 | 97 | 8 | 13 | n/a |
| GHSA | 2025→2026-05-31 | 98 | 3 | 4 | n/a |
| GHSA | 2026-05-31→current | 100 | 0 | 0 | n/a |
| CVE List | 2024→2025 | 100 | 99 | 99 | n/a |
| CVE List | 2025→2026-05-31 | 100 | 37 | 39 | n/a |
| CVE List | 2026-05-31→current | 100 | 0 | 1 | n/a |
| FKIE NVD mirror | 2024→2025 | 100 | 3 | 99 | 0 |
| FKIE NVD mirror | 2025→2026-05-31 | 100 | 2 | 4 | 0 |
| FKIE NVD mirror | 2026-05-31→current | 100 | 0 | 1 | 99 |

These counts are deliberately unlabelled. In particular, the CVE List 99/100
transition and the NVD 99/100 transitions are signatures that require bulk,
initial-population, schema, or sync classification before any natural-change
analysis. The 99/100 new NVD top-level `affected` transition after the last
checkpoint is consistent with the separately documented June 2026 schema and
bulk population event and is excluded from the correction route. No row in
this table is yet an `eligible_accepted_correction`.

## 5. Verification and evidence bindings

Remote commands completed successfully:

```text
python3 -m unittest discover -s experiments/temporal_provenance -p 'test_*.py' -v
# 16 tests, all PASS

python3 experiments/temporal_provenance/materialize_e0_git_states.py \
  --repositories-root data/raw/temporal_provenance/pilot_v1/repositories_full

python3 experiments/temporal_provenance/verify_e0_git_states.py
# pass, 240 present states, 0 failures

python3 experiments/temporal_provenance/analyze_e0_replay.py
# pass_e0_replay; NVD CPE/references 100/100
```

One reusable set of result bindings was recorded after the successful run:

| Remote artifact | SHA-256 |
|---|---|
| `data/processed/temporal_provenance/pilot_v1/e0_git_states/manifest.json` | `dc948440f92ef7f9b37f512b9b6a53f1e84b55e4e6346ffe3b2bd0bc7bdd4c6f` |
| `data/processed/temporal_provenance/pilot_v1/e0_nvd_current/manifest.json` | `9b38c29843c85d3ad54e908da32ed5d82d40ef297534be4e967b4b36d583617f` |
| `data/processed/temporal_provenance/pilot_v1/e0_nvd_current/records.jsonl` | `a72122df62969018e661e083bcd8779b9565de0bb258512e29fc7a77b4a051ae` |
| `results/temporal_provenance/pilot_v1/e0_replay/independent_parser_verification.json` | `85ee45651c0de1496e259a9d10cc6e0423ace817f57d2e133683ed0d2466c20b` |
| `results/temporal_provenance/pilot_v1/e0_replay/analysis.json` | `5f445a37d8473d9655c7dcfc50fc78b307993005196e203745164f77ed6b46b9` |

The hashes bind this run; they do not add semantic evidence.

## 6. Decision and next gate

Decision: `ADVANCE_TO_ACCEPTED_EVENT_DISCOVERY`.

This is not `GO_FOR_CONFIRMATORY_DESIGN`. The broad route still stops or
shrinks if either field has fewer than 50 eligible public accepted corrections,
if more than 5% lack replayable historical payloads, if either downstream task
cannot run on 50 events, if a bulk transaction dominates, or if closest work
already delivers the same complete task.

The literature qualification is recorded separately in
`docs/related_work_temporal_provenance_qualification_20260831.md`. Its strongest
current warning is that affected-version truth and NVD correction are already
strongly occupied, while VFC discovery and accepted GHSA contributions are
also occupied. The remaining candidate contribution therefore requires the
full accepted-event, historical-replay, explicit-lineage, two-consumer chain.
