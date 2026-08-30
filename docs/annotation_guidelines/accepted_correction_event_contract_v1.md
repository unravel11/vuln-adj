# Accepted Correction Event Contract V1

**Frozen**: 2026-08-31 before event discovery  
**Applies to**: temporal-provenance qualification pilot V1

## 1. Required event identity

An event key is:

`provider | cve_id | field | accepted_disposition_id | before_state_id | after_state_id`

All six parts are required. A row with an unknown state remains in the ledger
as unresolved and is not silently dropped.

## 2. Admission criteria

Label a candidate `eligible_accepted_correction=true` only when every condition
below is mechanically supported:

1. **Public disposition**: a provider or its documented curation workflow
   publicly accepted or merged the proposed change. A commit appearing on a
   mirror, an NVD `Changed` event, or a later `modified` timestamp alone is not
   accepted disposition.
2. **Exact object**: the disposition and both states map to the same CVE and
   advisory/package object. Ambiguous multi-CVE or multi-package mappings are
   unresolved unless the patch gives separable file-level changes.
3. **Tracked field**: the semantic diff changes affected package/range data or
   direct fix/patch/commit/pull-request references. Formatting, order, generated
   metadata, timestamps, or unrelated fields do not qualify.
4. **Stable before**: the state immediately before the accepted change is
   available as raw bytes and was not a known short-lived mirror rollback.
5. **Stable after**: the accepted semantic change appears on the provider's
   public main state within 14 days of disposition and remains present for at
   least seven days or through the next semantic edit, whichever occurs first.
6. **No future input**: selection uses disposition, file paths, CVE identity,
   field paths, and timestamps only. It does not inspect downstream output or
   whether the change agrees with an external benchmark.
7. **Complete lineage**: raw object digests, repository/endpoint identity,
   commit or event IDs, parser version, normalized projection, task input, and
   task output can be joined without a heuristic many-to-many merge.

## 3. Mandatory classifications

Each candidate receives exactly one primary disposition:

- `eligible_accepted_correction`
- `accepted_but_main_state_unmapped`
- `accepted_but_field_out_of_scope`
- `accepted_but_semantic_noop`
- `ordinary_provider_change_no_public_acceptance`
- `bulk_or_schema_event`
- `mirror_backfill_or_rollback`
- `ambiguous_object_mapping`
- `historical_payload_unavailable`
- `outside_frozen_interval`
- `unresolved_other`

Exclusion counts and denominators are outputs. Do not erase an ineligible
candidate from the raw ledger.

## 4. Field projections

### 4.1 Affected package/range

Preserve all packages, ecosystem identifiers, explicit versions, all range
types, every ordered range event, database-specific last-known ranges, and raw
source paths. Multiple `introduced`, `fixed`, `last_affected`, or `limit`
events must not be truncated to the first event.

The canonical projection may normalize key order and exact duplicate entries.
It must not infer package lineage, release ordering, range membership, or
equivalence across ecosystems. Those are downstream, evidence-bound steps.

### 4.2 Fix references

Preserve raw URL, source-provided type/tags, source record, and list position.
Canonicalization may normalize host case, default ports, trailing `.git`, and
known GitHub/GitLab commit or pull URL syntax. A repository URL, issue, compare
view, release page, and exact commit remain different resource types.

`known_vfc_match` requires an external mapping to the same CVE, repository
identity, and full commit identity or a documented unambiguous prefix. URL
shape alone is not a fixing-commit oracle.

## 5. Transaction and stability rules

- Use parent and child Git object IDs, not wall-clock ordering alone, for Git
  state transitions.
- Keep author time and committer time separately when both exist.
- Detect commits that touch unusually many advisory files; tag rather than
  assume they are natural corrections.
- If a semantic change is reverted within seven days, label the episode
  transient. A later reapplication is a distinct candidate event.
- A record's internal `modified` value does not override the repository tree
  state and cannot prove when the public mirror exposed the change.
- Provider sync, schema migration, path rename, bulk date repair, and generated
  reorder events are retained but excluded from the natural-correction main
  analysis.

## 6. Independent evidence boundary

Accepted disposition proves adoption by the named maintenance workflow. It
does not automatically prove factual truth, completeness, affected-version
membership, vulnerability-fixing semantics, or that later state is superior
for every consumer.

External affected-version benchmarks and CVE-to-VFC maps are separate evidence
layers. Report their version, scope, exact overlap, and license. A model,
scanner, current database snapshot, same-family LLM review, or this contract's
mechanical validator is not independent semantic truth.

## 7. Fail-closed behavior

Any missing required identity, raw state, stable mapping, or provenance join
sets the candidate to an unresolved/ineligible classification. The pipeline
must not fill missing historical values from the current record, carry an
after value backward, or select a neighboring commit because it yields a
cleaner downstream comparison.

