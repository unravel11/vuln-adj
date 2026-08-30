# Temporal Provenance Pilot V1: Pre-Acquisition Errata 1

**Recorded**: 2026-08-31  
**Timing**: after repository source pins were requested, before E0 sample
materialization, historical field comparison, event discovery, or downstream
results  
**Reason**: source-level schema and history audit, not observed pilot outcomes

This erratum narrows implementation details without changing the frozen
fields, checkpoints, downstream tasks, discovery interval, thresholds, or
claim ceiling.

## E1. Historical alignment is rebuilt as of each checkpoint

The 100-CVE manifest selected from the current aligned corpus is an engineering
replay audit only. It cannot estimate a historical bilateral population.

At every checkpoint, GHSA aliases and CVE identities must be read from the
checkpoint tree and the NVD/CVE/GHSA alignment must be rebuilt from those
as-of states. A current GHSA path or current CVE alias may locate a candidate
for the E0 extraction test, but cannot make a record count as historically
present or historically aligned. The pipeline reports current-path dependence
and as-of alias absence explicitly.

## E2. Two affected lineages remain separate

NVD `configurations`/CPE applicability is the affected-version field used by
the existing project. The newer NVD top-level `affected` payload copied from
CVE records is a different lineage. It must be stored separately and must not
replace, augment, or repair CPE configurations.

NVD Change History can conditionally reconstruct normalized CPE/range semantics
but may not recover raw `matchCriteriaId` identity. The top-level `Affected`
history currently lacks historical payloads and therefore starts as
`exact_replay_no_go`; CVE List Git states describe CVE source records, not an
exact historical NVD ingestion snapshot.

## E3. E0 is stricter than the scale gate

For the 100-CVE E0 sample, Git current-state extraction and each admitted
normalized NVD projection must agree on `100/100` records or stop for diagnosis.
The protocol's `99.5%` replay threshold applies only to a later scaled corpus
where each residual is classified and independently audited.

## E4. Git cutoff and transient handling

Select GHSA cutoff commits from the first-parent main history. Prefer official
CVE List baseline/hourly tags when an exact frozen checkpoint tag exists;
otherwise use the first-parent commit at or before the checkpoint. Repository
path moves, backfills, bulk syncs, and short-lived delete/revert episodes remain
explicit states and never become natural corrections by default.

