# When Vulnerability Metadata Differ: Routing Trade-Offs across Field-Level NVD–GHSA Strategies

> **ZERO DRAFT -- NOT AUTHOR APPROVED -- NOT SUBMISSION READY**
>
> This English zero draft is intentionally result-neutral. The title, thesis,
> RQ1--RQ3, exactly three contribution ceilings, and dual result branches were
> author locked at S2 on 2026-08-26 and then relocked after an author-triggered
> routing-centric rebalance; the prose itself is not author approved. RQ3
> contains an explicit placeholder because no real-human return exists.
> Citations and venue formatting remain provisional. The authoritative
> claim/evidence boundaries are `PAPER_BRIEF.md`, `EVIDENCE_LEDGER.md`,
> `CLAIM_LEDGER.md`, `FRAMING_CANDIDATES_AND_RESULT_BRANCHES_20260825.md`,
> and `FRAMING_REBALANCE_LOCK_RECORD_20260826.md`. The earlier
> `FRAMING_LOCK_RECORD_20260826.md` is superseded history.

## Abstract

**[WITHHELD UNTIL HUMAN RESULTS]** JSS requires a factual abstract of at most
250 words. Writing the RQ3 result or conclusion now would prejudge the human
study. The final abstract must report the frozen corpus, deterministic RQ1/RQ2
findings, the action-first/reason-second validation protocol, both
reviewer-specific outcomes, the selected positive or boundary branch, and the
explicit non-claims.

**Candidate keywords (not author approved):** vulnerability metadata;
vulnerability databases; discrepancy analysis; human judgment; abstention;
maintenance routing.

## 1. Introduction

Public vulnerability records are used to prioritize remediation, identify
affected software, and connect advisories to supporting evidence. The National
Vulnerability Database (NVD) and the GitHub Advisory Database (GHSA) both
publish structured records indexed by Common Vulnerabilities and Exposures
(CVE) identifiers, yet aligned records need not encode severity, affected
versions, publication time, or references in the same way. Such differences
matter to downstream consumers, but a difference is not self-interpreting. Two
strings can differ while denoting the same value; one record can contain a
strict subset of the other; timestamps can reflect different publication
events; and available evidence can be insufficient to determine whether a
factual conflict exists.

Prior work already establishes that vulnerability reports and databases can
differ. VIEM compared version information extracted from public vulnerability
reports with NVD records. Croft et al. (2022) studied severity inconsistency
across the Firefox vulnerability-reporting lifecycle and showed that the choice
of label source can alter downstream prediction results. Sun et al. (2023)
defined aspect-level discrepancies across heterogeneous vulnerability reports,
and Li et al. (2025) proposed VuldiffFinder for semantic inconsistencies in
unstructured vulnerability information. Other studies audit NVD quality,
estimate latent source quality, automate vulnerability curation, or evaluate
affected-version tools. Consequently, neither the existence of differences nor
field/aspect-level discrepancy detection is a defensible novelty claim for this
study.

The unresolved problem considered here is narrower. For a CVE-aligned pair of
structured records, what maintenance action, if any, should follow an observed
field difference? Escalating every non-equal value treats representation,
incompleteness, temporal lag, and factual conflict as interchangeable. A
field-specific strategy can avoid that collapse, but its rules may still encode
unvalidated assumptions. A type-first strategy can route different discrepancy
types to different actions, but the taxonomy cannot be used to define its own
success. The relevant comparison therefore requires action judgments obtained
independently of policy output, explicit uncertainty, and a strong simple
comparator rather than only raw string inequality.

We study four fields in a frozen corpus of 8,066 CVE-aligned NVD--GHSA record
pairs: severity, affected versions, publication date, and references. We first
report a deterministic, label-free census of 32,264 field instances. We then
compare three frozen routing strategies: a strong field-aware simple comparator,
a current type-first candidate, and an abstention-aware type-first candidate.
Finally, as a validation instrument rather than the paper's research object, a
V3.1 protocol asks two independent doctoral-student trained analysts to assign
maintenance actions before seeing or assigning discrepancy reasons. The action
stage is locked before the reason stage so the taxonomy does not define its own
action reference.

The study is organized around three neutral research questions:

- **RQ1 -- Deterministic discrepancy landscape.** Across 8,066 CVE-aligned
  NVD–GHSA record pairs, how do deterministic field statuses distribute for
  severity, affected versions, publication date, and references?
- **RQ2 -- Deterministic routing comparison.** How do three frozen routing
  strategies—a strong field-aware simple comparator, a current type-first
  candidate, and an abstention-aware type-first candidate—allocate field
  instances across actions, and where do their conflict-escalation, abstention,
  and total manual-route outputs differ across fields and statuses?
- **RQ3 -- Analyst-bounded validation.** When two independent trained analysts
  assign maintenance actions to the same frozen formal cases, do their
  judgments differentiate the three routing strategies in a consistent
  direction, and where do reliability, agreement, coverage, abstention, or
  shared-miss boundaries emerge?

The study adopts the following result-neutral thesis: For CVE-aligned NVD–GHSA
record pairs across four fields, three frozen routing strategies produce
different conflict-escalation, abstention, and total manual-route allocations;
independent trained-analyst judgments test whether those deterministic
differences correspond to differentiated maintenance actions or expose an
empirical decision boundary.

At the present evidence cutoff, deterministic RQ1 and RQ2 findings and protocol
claims are available. The strategies make different deterministic decisions,
but no strategy is known to be correct, safer, cheaper, or superior. RQ3
therefore preserves two result branches. If both reviewers independently clear
the frozen reliability, paired-direction, event-floor, coverage, and manual-loss
gates, the paper can report sample- and analyst-bounded strategy
differentiation. Otherwise, it reports the observed decision or identifiability
boundary and retains all failed gates, disagreements, abstentions, and uncertain
outcomes.

The author-locked contributions, subject to this ceiling, are exactly three:

1. **a reproducible four-field deterministic census:** a snapshot- and
   pipeline-bounded census of 8,066 CVE-aligned NVD--GHSA pairs and 32,264 field
   instances, with deterministic statuses for severity, affected versions,
   publication date, and references;
2. **a decision-oriented three-strategy routing comparison:** a frozen
   comparison with explicit conflict-escalation, abstention, and total-manual-
   route accounting, including a deterministic 74-fewer-conflicts/950-more-
   manual-routes contrast that is not correctness, workload, safety, utility,
   or superiority; and
3. **a sample- and analyst-bounded validation or decision boundary:** a frozen
   two-analyst evaluation whose valid returns support either reviewer-consistent
   strategy differentiation or the observed reliability, agreement, coverage,
   abstention, shared-miss, or identifiability boundary.

Action-first/reason-second ordering, recursive blinding, stage locks, and stop
rules are Method safeguards supporting contribution 3, not a standalone
contribution. The retrospective reconciliation-limit material supports the
discussion but is not counted as a fourth contribution.

We do not rank NVD and GHSA by global quality or authority, treat deterministic
statuses as truth, claim practitioner behavior, infer labor time from routing
counts, or claim temporal generalization.

## 2. Background and Task Definition

### 2.1 Research object

The unit of alignment is a CVE identifier shared by an NVD record and a reviewed
GHSA record under the repository's frozen data pipeline. The unit of analysis
is a field instance `(CVE, field, NVD value, GHSA value)`. CVE alignment is a
reference relation supplied by upstream identifiers; it is not independent
pairwise semantic adjudication and does not cover records without a usable CVE
identifier, ambiguous multi-CVE mappings, or true no-match cases.

The four primary fields are severity, affected versions, publication date, and
references. CWE identifiers are excluded from the low-human V3.1 study and may
appear only as retrospective or supplementary evidence. Each field has a
different identity contract. Severity comparison must distinguish missing
scores, representation, and materially different values. Affected-version
comparison depends on product/package identity and range semantics. Publication
dates can refer to different source events rather than a single universal
timestamp. Reference comparison is set- and URL-sensitive and can expose
aliases, source additions, or inaccessible evidence.

### 2.2 Observation, reason, and action

The deterministic pipeline assigns one of five statuses when its field-specific
rules permit: equivalent (`EQ`), representation discrepancy (`RD`), incomplete
(`INC`), temporal discrepancy (`TD`), or factual conflict (`FC`). The human
protocol additionally permits `uncertain`. These labels describe a proposed
reason for an observed difference. They are not source-truth labels.

Maintenance action is recorded separately: `no_action`, `enrich_record`,
`wait_for_sync`, `conflict_escalation`, or `abstain`. `Conflict_escalation`
places a case in a conflict queue. `Abstain` also routes a case to manual review
but does not assert that a factual conflict exists. We therefore define total
manual route as `conflict_escalation + abstain`; it is a count of strategy
outputs, not elapsed labor, monetary cost, or observed operational workload.

### 2.3 Separation from factual source adjudication

The routing task asks what should happen next under the visible record context.
It does not require an analyst to declare NVD or GHSA globally authoritative.
When the visible material cannot support an action or reason, abstention and
uncertainty remain admissible outcomes. Historical evidence-driven source
adjudication experiments are retained only as bounded failure evidence because
their non-human cohorts and abstentions cannot supply the independent action
oracle required here.

## 3. Related Work

### 3.1 Vulnerability-report and database discrepancies

Dong et al.'s VIEM work established a pipeline for extracting version
information from public vulnerability reports and comparing it with NVD. Croft
et al. (2022) measured severity disagreement across Bugzilla, Mozilla
advisories, and NVD, then examined how label-source choice affected downstream
prediction. These studies motivate field-specific analysis and show that source
selection can matter, but neither provides the four-field NVD--GHSA action
oracle used in this study.

Sun et al. (2023) are the most direct novelty constraint. Their TOSEM study
aligns heterogeneous reports, extracts seven vulnerability aspects, and studies
aspect-level discrepancy types and detection. Li et al. (2025) likewise treats
unstructured semantic inconsistency as an automatic detection task. Their
existence rules out a `first discrepancy taxonomy` contribution. Our locked
differential is instead the structured-input maintenance decision: independent
actions are collected before reasons, the main comparator is field-aware rather
than raw inequality, abstention is counted explicitly as manual routing, and a
failed reliability, coverage, or manual-loss gate is retained as a valid
boundary outcome.

### 3.2 Metadata quality, curation, and affected versions

NVD-focused quality studies have evaluated completeness, consistency, and
automatic correction candidates. Automated vulnerability-curation work maps
text to structured attributes and relates prediction quality to timeliness or
estimated curation effort. These studies provide a stronger evaluation model
than discrepancy counts alone, but attribute generation is not the same task as
routing a disagreement between two already structured sources.

Affected versions deserve separate treatment because range semantics depend on
release histories, branches, backports, and artifact identity. The ASE 2025
study *Vulnerability-Affected Versions Identification: How Far Are We?*
provides a benchmark of 1,128 C/C++ vulnerabilities and evaluates 12 tools on a
common task contract. It is the closest same-field external benchmark, not a
direct routing baseline. We have not reproduced those tools on the present
corpus and do not claim to improve on them. Their limitations support allowing
unresolved outcomes; they do not validate our field rules.

### 3.3 Selective prediction and human routing

Selective classification and learning-to-defer formalize the decision to
predict automatically or route a case elsewhere. Mozannar and Sontag (2020)
jointly learn a classifier and rejector from labels and expert decisions under a
system loss. The analogy is useful because deferral value depends on both the
machine and the downstream decision maker. The present study, however, does not
learn a rejector and currently has no returned human decision data. The three
strategies are deterministic and frozen before human exposure. Accordingly,
learning-to-defer is a theoretical closest family rather than a reproduced
same-task algorithm.

### 3.4 GHSA process and temporal interpretation

The MSR 2026 GHSA review-pipeline study characterizes reviewed and unreviewed
advisories, two review-latency regimes, and the relationship between advisory
origin and review timing, with released data and analysis code. This evidence
helps explain why publication dates across sources may encode different
processes. Review status and latency do not establish field correctness, and the
study cannot turn the present snapshot-external cohort into temporal
generalization evidence.

### 3.5 Positioning summary

The literature already supports discrepancy detection, metadata-quality audit,
attribute generation, affected-version benchmarking, and human deferral as
separate research routes. No public asset in the audited set supplies the same
four structured fields, action vocabulary, two independent action-first/reason-
second trained-analyst passes, and three frozen routing strategies. This is a
task-contract gap, not proof that the proposed construct is reliable or useful.

## 4. Corpus and Deterministic Analysis

### 4.1 Data sources and alignment

The frozen pipeline normalizes NVD and reviewed GHSA records and aligns them by
CVE identifier. The resulting field-view file contains 8,066 aligned record
pairs. V3.1 uses four fields per pair, yielding 32,264 field instances. The
authoritative field-view SHA-256 is
`c4bb405399bd0050c206b63ece95771c4f566a9a3968f123a16cf02a3b5cc3a2`.
The corpus supports statements about this snapshot and pipeline only. It is not
a probability sample of all vulnerability records, and CVE alignment excludes
important open-world matching cases.

### 4.2 Frozen strategies and reference arms

`field_aware_simple_v1` is the main strong comparator. It maps field-specific
conditions directly to maintenance actions without using the full type-first
mapping. `type_first_current_v1` is the current type-first candidate. It maps
the current deterministic status to an action and does not explicitly abstain.
`type_first_abstention_v1` is the abstention-aware type-first candidate; it
routes selected uncertain or insufficiently identifiable conditions to
`abstain`.

Four additional arms bound the comparison. `binary_observed_non_equal` and
`binary_canonical_non_equal` escalate raw and canonical non-equality,
respectively. `always_manual` routes every instance to conflict escalation, and
`abstain_all` routes every instance to abstention. The binary arms are lower
references; they are not the main comparator. The boundary arms are not
deployment recommendations.

### 4.3 Reproducibility and claim boundary

The label-free analyzer and independent verifier bind the field view, strategy
implementation, counts, and sampling capacity. Their agreement establishes
mechanical reproducibility of the deterministic outputs. It does not establish
that a status or action is correct. The output census was used only to determine
whether a fixed human sample could contain policy-disagreement and
shared-no-manual cases without changing the already frozen study objective.

## 5. Analyst-Bounded Validation Protocol

### 5.1 Reviewer role and bounded calibration

The intended reviewers are two different doctoral-student trained analysts. The
study does not claim practitioner expertise or observed production-maintainer
behavior. Reviewer-side work is independent and excludes AI assistance under an
author attestation that Codex did not independently verify.

V3.1 contains 20 calibration-1 cases, a CVE-disjoint 20-case calibration-2
reserve, and 120 formal cases. Calibration-2 is opened only if calibration-1
action agreement is below 0.60 or the guideline changes materially. A second
action agreement below 0.60 terminates formal distribution. The formal
allocation is 50 severity, 50 affected-version, 10 publication-date, and 10
reference cases. All cases are unique within phases, and phase CVE sets are
pairwise disjoint.

### 5.2 Action first, reason second

Each reviewer first assigns an action using the visible record pair and allowed
context. The return is validated and the action stage is hash-locked before any
reason packet is released. Only then does the reviewer assign `EQ`, `RD`, `INC`,
`TD`, `FC`, or `uncertain`. This ordering prevents the project's taxonomy from
directly defining the action used to evaluate routing utility. It does not
eliminate all anchoring: the same person sees the same case twice, so
same-reviewer action--reason association is treated as an upper bound.

### 5.3 Blinding and file governance

Reviewer-visible objects use recursive allowlists. Policy outputs,
deterministic statuses, selection cells, weights, AI candidates, prior reviews,
the other reviewer's materials, and future-stage packets are excluded. URLs can
reveal source identity, so the protocol is policy-blinded but not perfectly
source-blinded. Reviewer-specific distribution bundles currently contain only
the approved guideline, instructions, and calibration-1 action CSV.

### 5.4 Formal estimands and stop rules

Pre-adjudication analysis reports reviewer-specific raw action agreement,
nominal Krippendorff alpha, uncertainty, disagreement matrices, and reason
agreement as RQ3 validity diagnostics. Cross-reviewer action--reason association
is primary; same-reviewer association is secondary. RQ3 uses paired action
matches on strategy-disagreement rows, exact McNemar discordance, blocked
intervals, manual-route coverage, abstention, and design-weighted sensitivity.
Reviewer results are not pooled to manufacture a direction.

The formal set also contains a fixed 34-case shared-no-manual audit (15 severity
and 19 affected-version cases). It is a falsification opportunity: a human
conflict action can reveal a shared miss. It is not a population miss-rate
sample. Branch P requires, for each reviewer, at least 29 human conflict
actions, no lower type-first manual coverage, a one-sided simple-only-loss upper
bound below `delta_manual=0.10`, the frozen paired direction, and no
contradictory systematic failure. If either reviewer fails, the positive route
stops. Passing these study gates would not establish operational safety.

### 5.5 Adjudication

Author adjudication, if performed, is policy-blinded, secondary, and reported
after the pre-adjudication results. A sensitivity analysis excludes every
adjudicated case. Adjudication cannot be used to repair low independent
agreement or reverse a failed policy gate.

## 6. Results

### 6.1 RQ1 -- Deterministic discrepancy landscape

The deterministic census contains 8,066 observations for each of the four
fields. Severity was classified as 3,106 equivalent, 3,178 representation
discrepancy, 33 incomplete, and 1,749 factual conflict. Affected versions
contained 425 equivalent, 3,936 representation discrepancy, 3,054 incomplete,
and 651 factual conflict instances. Publication date contained 6,169
representation and 1,897 temporal discrepancies. References contained 300
representation discrepancies, 7,763 incomplete instances, and three factual
conflicts. These counts are rule outputs, not verified factual labels or
database-quality measurements.

**Answer to RQ1.** The frozen field rules produce a heterogeneous landscape.
Representation differences dominate severity and publication date, while
incomplete values dominate references; affected versions are distributed
across representation, incomplete, equivalent, and conflict statuses. This
answer is limited to the frozen corpus, field contracts, and deterministic
implementations.

### 6.2 RQ2 -- Deterministic routing comparison

The strong field-aware and abstention-aware type-first strategies made different
actions on 2,332 instances: 263 severity, 1,766 affected-version, zero
publication-date, and 303 reference instances. Across the complete corpus, the
abstention-aware strategy produced 1,706 conflict escalations versus 1,780 for
the strong comparator, a difference of -74. When abstentions were also counted
as manual routes, the corresponding totals were 4,126 and 3,176, a difference
of +950. The two deterministic summaries therefore move in opposite
directions. They establish a queue-allocation trade-off; they do not demonstrate
saved work, safety, utility, or superiority.

**Answer to RQ2.** The frozen strategies allocate the same field instances
differently, with most disagreement concentrated in affected versions and none
between the two reported strategies for publication date. A smaller conflict
queue coexists with a larger total manual route once abstention is counted. This
is a deterministic output comparison, not a ranking of operational value.

### 6.3 RQ3 -- Analyst-bounded validation

**[REAL-HUMAN RESULTS PLACEHOLDER -- DO NOT PRESELECT A RESULT BRANCH OR FILL
WITH AI/SYNTHETIC DATA]**

Required content after E08/E09 are valid:

- reviewer A and B action distributions, including abstain;
- raw action agreement and nominal Krippendorff alpha overall and by field as
  validity diagnostics;
- reason distributions, uncertainty, disagreement matrices, cross-reviewer
  action--reason association, and the same-reviewer upper bound;
- the calibration path actually used and any pre-formal guideline diff;
- paired action-match differences and exact discordance for each reviewer;
- agreement controls separated from policy-disagreement rows;
- conflict queue, abstention, and total manual-route coverage;
- the 34-case shared-no-manual audit outcome with a sample-conditional boundary;
- whether each reviewer independently cleared the 25/29 event thresholds and
  `delta_manual=0.10` gate;
- design-weighted sensitivity, effective sample size, and adjudication-exclusion
  sensitivity;
- explicit retention of failed fields, uncertain outcomes, disagreements, and
  systematic field-specific failure candidates.

**Branch P template:** use only if both reviewers clear every frozen positive
gate and support the same direction. State the result for this sample and these
trained analysts; do not claim human gold, practitioner consensus, time savings,
deployment safety, or universal superiority.

**Branch B template:** use if calibration terminates or a reliability, paired-
direction, event-floor, coverage, or manual-loss gate fails. Report that the
tested deterministic strategies did not support stable reviewer-consistent
differentiation under the frozen contract, then identify the observed boundary
without changing fields, cases, strategies, thresholds, or labels.

## 7. Discussion

### 7.1 What RQ1 and RQ2 already establish

RQ1 establishes the snapshot-bounded discrepancy landscape. RQ2 establishes
that routing choices are consequential at the level of deterministic output: a
smaller conflict queue can coexist with a larger total manual route once
abstention is counted. This distinction prevents an accounting artifact in
which abstention is treated as free. It does not determine which queue is
operationally preferable.

### 7.2 Interpretation under the positive branch

**[CONDITIONAL]** If both reviewers clear the frozen gates, interpret the result
as a bounded comparison of decision policies under independent trained-analyst
actions. Discuss which fields carry the signal and whether abstention changes
coverage as intended. Keep source correctness and actual maintenance effort
outside the conclusion.

### 7.3 Interpretation under the boundary branch

**[CONDITIONAL]** If the gates fail, treat disagreement as a result rather than
noise to be repaired. Possible evidence-bounded interpretations include an
insufficient information contract, field-dependent ambiguity, unstable action
semantics, or a shared blind spot. Select only interpretations supported by the
observed matrices and failure cases. A failed positive route does not prove that
all vulnerability-metadata routing is infeasible.

### 7.4 Reconciliation limits

Historical non-human adjudication cohorts show that automated reconciliation
can be evidence-dependent and frequently unresolved under tested protocols.
Those artifacts can explain why explicit abstention was retained. They cannot
be merged with V3.1 human outcomes, presented as a successful adjudication
method, or used to rank NVD and GHSA.

## 8. Threats to Validity

**Construct validity.** Maintenance actions are study constructs, not direct
logs of production curator behavior. The reviewers are trained analysts rather
than practitioners. Action-first ordering reduces taxonomy circularity but does
not eliminate repeated-case anchoring. URLs may reveal source identity. We
report uncertainty and pre-adjudication agreement, and a low calibration or
formal reliability result terminates positive claims.

**Internal validity.** The deterministic field rules can be wrong even when
their implementation is reproducible. Sampling is stratified around policy
comparison and includes a fixed shared-no-manual audit; it is not an unqualified
random sample of all instances. Policies, cells, thresholds, and analysis were
frozen before human exposure. Reviewer-specific results and exact paired
comparisons reduce, but do not remove, dependence on the chosen loss and action
contract.

**Conclusion validity.** A limited number of human conflict actions may make
Branch P statistically unidentifiable. The frozen 25/29 floors and one-sided
manual-loss upper bound control the permitted branch rather than guaranteeing a
positive result or operational safety. Weighted sensitivity can have low
effective sample size and does not replace the primary paired analysis.
Multiple field-level summaries are descriptive unless a correction or
confirmatory hierarchy was frozen.

**External validity.** The corpus contains CVE-aligned NVD and reviewed GHSA
records under one snapshot and pipeline. It excludes unmatched, no-CVE,
ambiguous multi-CVE, and broader advisory ecosystems. Results may not transfer
to other sources, future snapshots, unreviewed GHSAs, or practitioner workflows.
The current snapshot-external data are not a bilateral post-freeze temporal
cohort.

**Reproducibility and artifact validity.** Hashes, manifests, validators, and
independent mechanical verifiers bind files and computations. They do not prove
semantic truth or submission readiness. Real returns may contain private or
sensitive reviewer information; public artifacts must separate anonymized
analysis data from reviewer-private materials and comply with the final author
and institutional disposition.

## 9. Conclusion

**[WITHHELD UNTIL RESULT BRANCH SELECTION]**

The final conclusion must first restate the snapshot-bounded RQ1/RQ2 findings,
then give either the reviewer-consistent Branch P result or the preserved Branch
B boundary for RQ3. It must not claim database authority, practitioner behavior,
labor savings, population safety, temporal generalization, or submission
readiness.

## Provisional References Requiring Final BibTeX Reconciliation

- Croft, R., Babar, M.A., Li, L., 2022. An Investigation into Inconsistency of
  Software Vulnerability Severity across Data Sources. SANER, 338--348.
  https://doi.org/10.1109/SANER53432.2022.00050
- Li, Q., Tang, W., Chen, X., Ren, H., 2025. VuldiffFinder: Discovering
  Inconsistencies in Unstructured Vulnerability Information. Computers &
  Security 154, 104447. https://doi.org/10.1016/j.cose.2025.104447
- Mozannar, H., Sontag, D., 2020. Consistent Estimators for Learning to Defer
  to an Expert. Proceedings of Machine Learning Research 119, 7076--7087.
  https://proceedings.mlr.press/v119/mozannar20b.html
- Sun, J., Xing, Z., Xia, X., Lu, Q., Xu, X., Zhu, L., 2023. Aspect-Level
  Information Discrepancies across Heterogeneous Vulnerability Reports:
  Severity, Types and Detection Methods. ACM Transactions on Software
  Engineering and Methodology 33(2), Article 49.
  https://doi.org/10.1145/3624734
- Chen, X., Liu, C., Cao, J., et al., 2025. Vulnerability-Affected Versions
  Identification: How Far Are We? ASE 2025, 2970--2982.
  https://doi.org/10.1109/ASE63991.2025.00244
- Segal, C., Segal, P., Banjar, C.E., et al., 2026. Characterizing and
  Modeling the GitHub Security Advisories Review Pipeline. MSR 2026.
  https://doi.org/10.1145/3793302.3793360

The final manuscript must add the remaining cited works, datasets, and software
as complete references and verify every author, title, venue, year, pagination,
DOI, version, and access date against primary sources.

## Required Declarations (Author-Owned Placeholders)

- **Data availability:** [AUTHOR TO COMPLETE; JSS Option C deposit/link or
  justified restriction required.]
- **Code availability:** [AUTHOR TO COMPLETE; archival version/PID and license
  unresolved.]
- **Funding:** [AUTHOR TO COMPLETE.]
- **Competing interests:** [AUTHOR TO COMPLETE.]
- **CRediT author statement:** [AUTHOR TO COMPLETE.]
- **Human participation / ethics determination:** [AUTHOR/INSTITUTION TO
  COMPLETE; do not upgrade R2 author attestation into independent verification.]
- **Declaration of generative AI and AI-assisted technologies:** [REQUIRED FOR
  AUTHOR REVIEW because Codex assisted preparation of this zero draft; specify
  tool, purpose, author review/editing, and full author responsibility using
  the current JSS wording.]
