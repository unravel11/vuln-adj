# JSS Argument Plan

Status: `S2_CANDIDATE_FOR_AUTHOR_APPROVAL`.

This plan defines the intended argument, not a completed manuscript or a
positive result. T1 and T2 outcomes may force a negative or construct-ambiguity
paper, but they may not be screened out to preserve the candidate thesis.

## Working title

Beyond Binary Mismatch: An Empirical Audit of Field-Level Reconciliation
between NVD and GHSA

## One-sentence candidate argument

A CVE-aligned field mismatch is an observation rather than a conflict verdict;
type-first routing with explicit abstention provides a testable way to separate
different maintenance actions and to expose the empirical limits of automated
reconciliation.

## Narrative spine

1. NVD and GHSA often encode aligned CVEs differently at the field level.
2. A binary mismatch collapses representation, incompleteness, timing, and
   incompatible facts into one action.
3. The project therefore tests a type-first taxonomy under independent human
   review instead of treating deterministic labels as truth.
4. The downstream test asks whether the taxonomy changes expert workload
   without concealing human-validated factual conflicts.
5. Existing evidence-driven adjudication results are retained as a bounded
   audit of abstention, evidence dependence, low coverage, and no-go outcomes.

Steps 3 and 4 are planned claims until T1 and T2 are complete.

## Research questions and decision roles

### RQ1 — Distribution

Rhetorical job: establish the frozen NVD–GHSA corpus, field view, deterministic
comparison outputs, and where differences occur.

Admissible claim: snapshot-bounded descriptive counts.

Forbidden upgrade: database correctness, factual-conflict prevalence, or causal
explanation.

### RQ2 — Construct and typing validity

Rhetorical job: test whether two real reviewers can use the five-way taxonomy
reliably and evaluate the deterministic baseline only after gold is frozen.

Admissible claim before T1: protocol and hypothesis only.

Admissible claim after T1: exact agreement, Krippendorff's alpha, uncertain
coverage, design-weighted confusion and performance, all reported by field.

### RQ3 — Operational value and limits

Rhetorical job: compare binary conflict escalation with a frozen type-first
action map, then explain where automated evidence-driven adjudication abstains
or fails against named baselines.

Admissible claim before T2: protocol and current retrospective no-go only.

Forbidden upgrade: deployment benefit, general source authority, or successful
affected-version adjudication.

## Contribution-to-evidence map

| Candidate contribution | Required evidence | Current disposition |
|---|---|---|
| Frozen-corpus field-level empirical audit | E01 | Available and bounded |
| Reliable action-oriented discrepancy taxonomy | E02 plus T1/E08 | Missing human validation |
| Reduced expert conflict-review workload at preserved recall | T1/E08 plus T2/E09 | Missing |
| Auditable limits of automated reconciliation | E04–E06 | Available only as retrospective negative/failure evidence |

## Section outline

1. Introduction
   - Define the operational cost of treating every mismatch as conflict.
   - State the human-validation and abstention requirements up front.
   - Do not lead with a claim of method superiority.
2. Background and Task Definition
   - Define the business objects: CVE-aligned record, field instance, observed
     difference, discrepancy type, conflict-review action, and source
     adjudication.
   - Separate typing from choosing which source is correct.
3. Related Work
   - Compare directly with cross-database vulnerability inconsistency studies,
     VuldiffFinder, and affected-version tool benchmarks.
   - Position the differential as action-oriented routing, abstention, and
     identifiability/failure analysis, not the first discrepancy taxonomy.
4. Corpus and Deterministic Field View
   - Describe NVD/GHSA snapshots, CVE alignment, fields, exclusions, and
     normalization.
   - Bind every count to E01.
5. Type-First Method and Human Protocol
   - Present taxonomy and action map separately.
   - Describe sampling weights, blinding, dual review, uncertainty, and
     adjudication.
6. RQ1 Results
   - Report only deterministic distribution and input-sensitivity checks.
7. RQ2 Results
   - Report T1 reliability, coverage, confusion, and field failures.
   - Preserve uncertain rows and any no-go field.
8. RQ3 Results
   - Report T2 workload/recall trade-offs.
   - Report existing adjudication no-go and evidence dependence in a separate
     subsection so it cannot masquerade as a successful method.
9. Discussion
   - Explain action-specific maintenance implications, identifiability limits,
     and when abstention is required.
10. Threats to Validity
    - Snapshot, CVE-alignment, stratified sampling, reviewer expertise,
      taxonomy construction, source blinding limits, dynamic evidence, and
      post-hoc historical analyses.
11. Conclusion
    - Match the strongest result that survives T1/T2; do not preserve the
      positive candidate thesis if a gate fails.

## Figure and table plan

| Artifact | Question | Evidence source | Planned role | Gate |
|---|---|---|---|---|
| Figure 1: task and routing flow | How does a field observation move from comparison to action or abstention? | Method contract | Define typing versus source adjudication | Conceptual only; no result styling |
| Table 1: corpus and field distribution | What was compared and how often did deterministic outputs occur? | E01 | RQ1 lookup table | Counts must trace to frozen field view |
| Figure 2: taxonomy and action map | Which labels imply no action, enrichment, freshness handling, or conflict review? | T1 codebook | Explain the operational differential | Freeze before T1 evaluation unsealing |
| Table 2: human reliability and coverage | Can reviewers apply the construct? | E08 | RQ2 primary evidence | Show all fields and uncertain counts |
| Figure 3: workload–conflict-recall trade-off | Does type-first routing improve the decision objective? | E09 | RQ3 primary comparison | Fixed comparator and action map |
| Table 3: automated adjudication limits | Where did methods cover, abstain, or lose to simple baselines? | E05–E06, and T3 if run | Negative/failure evidence | Keep protocols and denominators separate |

No temporal-generalization figure is planned. It may be added only if a new
eligible cohort is frozen before labels or results are observed.

## Related-work positioning contract

The manuscript must include and directly compare at least:

- the 2023 TOSEM aspect-level vulnerability database discrepancy study
  (DOI `10.1145/3624734`);
- VuldiffFinder's inconsistency categories and sample-based detection study;
- the public affected-version tool benchmark identified by arXiv
  `2509.03876`;
- source-specific vulnerability database quality, mapping, and reconciliation
  work already inventoried in `docs/related_work_survey.md`.

The paper may claim a differential only after a source-grounded comparison
table is written. The candidate differential is:

> CVE-aligned, field-level, action-oriented routing with explicit abstention,
> coupled with a human construct test and an empirical account of
> identifiability and failure.

## Writing order

1. Freeze and run T1.
2. Freeze and run T2.
3. Decide positive versus negative/construct-ambiguity framing.
4. Draft Methods and Results.
5. Draft Discussion and Threats.
6. Draft Introduction and Related Work.
7. Draft title, abstract, conclusion, highlights, and cover letter last.

## S2 lock gate

The argument can move to `S2_ARGUMENT_LOCKED` only when:

- the author approves the title direction, RQs, primary fields, and non-claims;
- the T1 protocol and codebook route are accepted before human labels;
- the T2 action comparator is fixed;
- the decision to keep or demote adjudication as a core contribution is
  recorded;
- no closest-related-work finding invalidates the differential.

If T1 reliability or T2 utility fails, the positive route stops. The paper may
continue only with the failure retained and an explicitly revised thesis.
