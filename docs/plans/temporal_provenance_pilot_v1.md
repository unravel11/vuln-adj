# Temporal Provenance Qualification Pilot V1

**Frozen on**: 2026-08-31, before pilot acquisition or result generation  
**Status**: `Q0_PROTOCOL_FROZEN`  
**Authoritative runtime**: `code-defender:/home/xiaoyuliang/code/vuln-adj`  
**Execution branch**: `codex/temporal-provenance-pilot-20260831`

## 1. Plain-language decision

This pilot asks whether there is a paper-sized problem behind a specific
failure mode: a study or tool can query a vulnerability database today and
silently obtain knowledge that the database did not contain at the historical
decision time. The candidate contribution is not the observation that records
change. It is a reproducible event ledger that connects an accepted metadata
correction to the historical record state and then to two different downstream
outputs.

The pilot returns `GO`, `PARTIAL`, or `NO_GO`. A runnable pipeline, a large
number of Git commits, or a statistically non-zero change count is not by
itself a `GO`.

## 2. Candidate question and differential

The qualification question is:

> When a vulnerability-metadata maintainer publicly accepts a correction to
> affected-package/range data or a vulnerability-fixing reference, can the
> pre-correction state be replayed, and does using the later state change an
> executable downstream artifact?

The closest-work burden is high. Existing work already studies cross-source
metadata discrepancies, severity evolution, GHSA review latency, affected-
version identification, vulnerability-fixing-commit retrieval, and accepted
GHSA reference contributions. This route survives only if it adds all of the
following on one auditable contract:

1. provider-accepted before/after correction events rather than arbitrary
   snapshot differences;
2. explicit public-transaction, record-time, and observation-time provenance;
3. replay at fixed historical checkpoints without future-state inputs; and
4. propagation into at least two distinct executable downstream consumers.

If the pilot can only count changed records, reproduce one affected-version
case, or repeat an accepted-reference study without downstream propagation,
the direction is `NO_GO`.

## 3. Units, fields, and clocks

### 3.1 Units

- **Record state**: one source's serialized record for one CVE at one Git
  commit or API observation.
- **Candidate change**: one stable before/after field projection for one CVE.
- **Accepted correction**: a candidate change that passes the separate event
  contract in
  `docs/annotation_guidelines/accepted_correction_event_contract_v1.md`.
- **Downstream observation**: the deterministic output of one frozen consumer
  on either the before or after task input.
- **Paired effect unit**: the before/after output difference for the same
  accepted correction and the same frozen consumer.

### 3.2 Fields

- Primary field A: package identity and affected-version ranges.
- Primary field B: direct fix/patch/commit/pull-request references.
- Provider-tagged CVSS may be retained as a secondary audit field only. It
  cannot replace either primary field for the two-task gate.
- Published, modified, commit, merge, and acquisition times are provenance
  axes, not semantic outcome labels.

### 3.3 Clocks

Every state or event keeps separate columns for:

- `provider_record_time`, when present in the record;
- `public_transaction_time`, the source Git commit time or API event time;
- `accepted_disposition_time`, when a public PR or equivalent disposition was
  accepted;
- `observed_at`, when this study acquired the object.

These clocks must not be substituted for one another. GHSA main is a public
mirror, so its Git commit time is a mirror transaction time, not GitHub's
internal curation time. The first large GHSA backfill and transient rollback
commits are not evidence of contemporaneous advisory state.

## 4. Sources and source ceiling

### 4.1 GHSA

Use `https://github.com/github/advisory-database.git` and pin every extracted
state to a full commit ID. A file is read from the repository tree at that
commit; the record's `modified` field is preserved separately. A merged public
improvement PR can establish accepted disposition, but the study must still
map it to a stable main-branch state.

### 4.2 NVD

Use the official NVD CVE API for current states and the official CVE Change
History API for event audit. The current API uses batched `cveIds`; the old
singular `cveId` behavior is not assumed. NVD affected-history entries that
only point to a current external payload are non-replayable unless a matching
historical provider-controlled state exists.

The FKIE `nvd-json-data-feeds` repository may materialize historical NVD API
snapshots for qualification. It is a community reconstruction, not an NVD-
endorsed version store. For any field admitted to the main analysis, its
current projection must be cross-checked against the official NVD API, and a
sample of its historical transitions must be reconciled with official Change
History.

### 4.3 CVE source records

`CVEProject/cvelistV5` is an official CVE List Git source and may supply CNA or
ADP affected data and provenance. It is not NVD. Its 2023 initial population,
path migration, later bulk date repairs, and schema-normalization events must
be identified and excluded or analyzed separately.

## 5. Frozen E0 replay audit

### 5.1 Input universe

Start from the existing 8,066 CVE-aligned NVD--reviewed-GHSA corpus only to
define IDs. Do not reuse its normalized affected/reference values as historical
truth because the old normalizers discard multi-event GHSA ranges, versions-
only details, NVD source identity, and reference types.

Eligibility is decided without reading historical differences or downstream
outputs:

1. a syntactically valid CVE ID;
2. one current NVD record and at least one current reviewed GHSA record;
3. NVD publication time no later than `2023-12-31T23:59:59Z`; and
4. at least one GHSA publication time no later than that same instant.

From eligible IDs, select exactly 100 by ascending
`SHA256("temporal-provenance-pilot-v1\n" + cve_id)`, with no replacement. If
fewer than 100 are eligible, freeze the full eligible universe and return
`PARTIAL_SOURCE_UNIVERSE` before downstream analysis.

### 5.2 Fixed checkpoints

- `2024-01-01T00:00:00Z`
- `2025-01-01T00:00:00Z`
- `2026-05-31T00:00:00Z`

The last checkpoint deliberately precedes the known June 2026 NVD bulk/schema
event. Checkpoints cannot be changed after observing field or task differences.

### 5.3 Replay checks

For each source and checkpoint, materialize the repository tree state and the
raw record bytes before normalization. Then:

1. re-materialize the current repository state through the same extractor;
2. compare normalized current projections with the official/current source;
3. independently parse 20 deterministic CVEs with a second minimal parser;
4. retain unresolved, absent, transient, and schema-unsupported states; and
5. record every exclusion reason with a denominator.

The replay audit is an engineering qualification. It does not establish that a
historical value was factually correct.

## 6. Frozen accepted-correction discovery

The discovery interval is
`2024-01-01T00:00:00Z <= accepted_disposition_time < 2026-01-01T00:00:00Z`.
Enumerate public accepted dispositions without filtering on effect direction,
field agreement, downstream output, or whether the after state looks better.

Create one candidate per CVE, field, and accepted disposition. Apply the event
contract mechanically. Preserve multiple events for the same CVE but use
cluster-aware inference and report CVE-level as well as event-level
denominators. Events caused by a bulk sync, schema migration, backfill,
timestamp-only rewrite, path migration, or a mirror rollback are tagged and
excluded from the natural-correction primary analysis.

The qualification target is at least 50 eligible accepted corrections for
each primary field. This is a feasibility floor, not a power calculation and
not a prevalence estimate.

## 7. Downstream tasks

### Task A: affected range to offline SCA alerts

Encode the before and after affected package/range projections as two frozen
OSV records. Run the same pinned offline scanner against the same frozen list
of package-version queries. The primary output is the paired change in the
alert set, with added and removed package-version alerts reported separately.

The preferred initial consumer is OSV-Scanner `v2.5.1`, pinned by binary digest
and source commit. Package release universes and query inputs must be acquired
and frozen without inspecting scanner output. If an external affected-version
benchmark has an exact ecosystem/package/CVE overlap, report agreement as a
separate validation subset; do not treat scanner behavior or accepted-after
metadata as universal ground truth.

### Task B: references to known fixing-commit coverage

Parse direct commit, pull-request, and patch references from the before and
after records under one frozen URL-identity contract. Evaluate whether a known
vulnerability-fixing commit is present using a versioned external CVE-to-VFC
mapping. Report coverage and false-link eligibility only where the external
mapping supplies a same-CVE repository/commit relation.

VFCFinder may be run as an optional ranking baseline only after its released
environment is reproduced. Its model output is not an oracle. Published
accepted PRs from that work may validate event lineage but cannot be counted as
an independent replication of the same contribution.

## 8. Analysis frozen before outcomes

For every field and task report:

- discovery, eligibility, replayable, and executable denominators;
- missing/absent/unresolved/transient/schema-event counts;
- paired before/after output transitions, not just marginal totals;
- event-level and CVE-clustered bootstrap 95% intervals when denominators permit;
- sensitivity excluding bulk commits, rollbacks, multi-advisory transactions,
  and corrections without exact main-state mapping; and
- source- and checkpoint-specific results without pooling incompatible clocks.

No null-hypothesis significance test is required for E0. A later confirmatory
test and power target can be frozen only after E0 establishes an effect unit
and variance without reusing the qualification sample for confirmation.

## 9. Stop and advancement gates

Return `NO_GO` for the broad two-field paper route if any of these holds:

1. current replay agreement for either primary field is below `99.5%`;
2. more than `5%` of candidate events for a primary field lack a recoverable
   historical payload and lack a contemporaneous provider-controlled Git state;
3. either primary field has fewer than 50 eligible accepted corrections in the
   frozen interval;
4. Task A or Task B cannot be executed on at least 50 eligible events;
5. observable output changes are produced almost entirely by one bulk/schema
   transaction, with no separable natural-correction cohort; or
6. the literature audit finds an existing study with accepted before/after
   corrections, explicit provenance, the same two downstream tasks, and a
   reproducible same-task artifact.

Return `PARTIAL` and shrink the route before any paper drafting if exactly one
field/task passes. Do not rename a one-field result as the original two-field
contribution. Return `GO_FOR_CONFIRMATORY_DESIGN`, not `paper ready`, only if
both fields and both tasks pass and the closest-work differential remains.

## 10. Claim ceiling

The strongest pilot-level claims are that public record states and executable
outputs differ across accepted corrections under the frozen lineage. The pilot
cannot by itself claim:

- that every accepted correction is semantically true;
- that NVD, GHSA, or CVE List is generally accurate or inaccurate;
- that a changed scanner alert is a true positive or false positive;
- that all prior studies contain leakage or that reported model accuracy is
  biased by a measured amount;
- real exploitability, remediation safety, workload reduction, prevalence, or
  causality outside the paired event; or
- novelty, submission readiness, or likely acceptance.

## 11. Frozen implementation order

1. commit this protocol, event contract, master-plan update, and progress log;
2. acquire/pin source repositories and build a raw provenance manifest;
3. build and seal the 100-CVE E0 manifest;
4. implement source-specific raw materializers and two independent parsers;
5. run current replay gates before reading historical output differences;
6. materialize fixed checkpoints and discover accepted corrections;
7. implement and smoke Task A and Task B;
8. run the frozen analysis and independent verifier; and
9. update the project ledgers with `GO_FOR_CONFIRMATORY_DESIGN`, `PARTIAL`, or
   `NO_GO` while preserving all unresolved states.

