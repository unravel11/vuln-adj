# When Vulnerability Metadata Differ: Routing Trade-Offs across Field-Level NVD–GHSA Strategies

> **ZERO DRAFT -- NOT AUTHOR APPROVED -- NOT SUBMISSION READY**
>
> RQ3 results, the abstract, and the conclusion remain withheld pending valid
> real-human returns. The title, thesis, research questions, three contribution
> ceilings, and dual result branches follow the S2 records in `PAPER_BRIEF.md`,
> `EVIDENCE_LEDGER.md`, `CLAIM_LEDGER.md`,
> `FRAMING_CANDIDATES_AND_RESULT_BRANCHES_20260825.md`, and
> `FRAMING_REBALANCE_LOCK_RECORD_20260826.md`. The checked citation source is
> `paper/jss/latex/references.bib`; the editable venue-source representation is
> `paper/jss/latex/main.tex`.

## Abstract

**[WITHHELD PENDING VALID RQ3 RESULTS]** The final abstract will report the
frozen corpus, deterministic RQ1/RQ2 findings, the action-first/reason-second
validation protocol, both analyst-specific outcomes, and the selected positive
or boundary branch in at most 250 words.

**Candidate keywords:** vulnerability metadata; vulnerability databases;
discrepancy analysis; human judgment; abstention; maintenance routing.

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
affected-version tools. Together, these studies establish discrepancy existence
and field/aspect-level detection as prior art. This study examines the next
maintenance decision for an observed field difference between two CVE-aligned
structured records.

Escalating every non-equal value treats representation,
incompleteness, temporal lag, and factual conflict as interchangeable. A
field-specific strategy can avoid that collapse, but its rules may still encode
unvalidated assumptions. A type-first strategy can route different discrepancy
types to different actions, but the taxonomy cannot be used to define its own
success. The relevant comparison therefore requires action judgments obtained
independently of strategy output, explicit uncertainty, and a strong simple
comparator rather than only raw string inequality.

We study four fields in a frozen corpus of 8,066 CVE-aligned NVD--GHSA record
pairs: severity, affected versions, publication date, and references. We first
report a deterministic, label-free census of 32,264 field instances. We then
compare three frozen routing strategies: a strong field-aware simple comparator,
a current type-first candidate, and an abstention-aware type-first candidate.
Finally, a V3.1 protocol evaluates these strategies using maintenance actions
assigned by two independent doctoral-student trained analysts. Analysts assign
actions before discrepancy reasons, so the taxonomy does not directly define
the action reference.

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

RQ1 and RQ2 are supported by deterministic evidence. RQ3 retains positive and
boundary branches pending valid analyst returns. Branch P requires both analysts
to clear the frozen reliability, paired-direction, event-floor, coverage, and
manual-loss gates. Otherwise, Branch B reports the observed decision or
identifiability boundary together with failed gates, disagreements, abstentions,
and uncertain outcomes.

The study has three contributions:

1. **a reproducible four-field deterministic census:** a snapshot- and
   pipeline-bounded census of 8,066 CVE-aligned NVD--GHSA pairs and 32,264 field
   instances, with deterministic statuses for severity, affected versions,
   publication date, and references;
2. **a decision-oriented three-strategy routing comparison:** a frozen
   comparison with explicit conflict-escalation, abstention, and total-manual-
   route accounting, including the deterministic result that the
   abstention-aware strategy produces 74 fewer conflict escalations and 950 more
   total manual routes than the strong field-aware comparator on this corpus;
   and
3. **a sample- and analyst-bounded validation or decision boundary:** a frozen
   two-analyst evaluation whose valid returns support either analyst-consistent
   strategy differentiation or the observed reliability, agreement, coverage,
   abstention, shared-miss, or identifiability boundary.

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
(`INC`), temporal discrepancy (`TD`), or factual conflict (`FC`). The analyst
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
selection can matter, but neither provides the four-field NVD--GHSA
maintenance-action reference required by this study.

Sun et al. (2023) provide the closest task-level comparison. Their TOSEM study
aligns heterogeneous reports, extracts seven vulnerability aspects, and studies
aspect-level discrepancy types and detection. Li et al. (2025) likewise treats
unstructured semantic inconsistency as an automatic detection task. These
studies cover discrepancy taxonomy and detection. Our study addresses a
different workflow step: routing differences between structured NVD and GHSA
records to maintenance actions. Actions are collected before reasons, the main
comparator is field-aware rather than raw inequality, abstention is included in
the total manual route, and frozen reliability, coverage, and manual-loss gates
separate strategy differentiation from boundary outcomes.

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
common task contract. It is the closest same-field external benchmark, although
its task is affected-version identification rather than cross-source routing.
Because we have not reproduced those tools on the present corpus, we use the
study to define the external task boundary and motivate unresolved outcomes,
not as a performance baseline for our field rules.

### 3.3 Selective prediction and human routing

Selective classification and learning-to-defer formalize the decision to
predict automatically or route a case elsewhere. Mozannar and Sontag (2020)
jointly learn a classifier and rejector from labels and expert decisions under a
system loss. The analogy is useful because deferral value depends on both the
machine and the downstream decision maker. The present study uses deterministic
strategies frozen before human exposure and does not learn a rejector. We
therefore use learning-to-defer as the closest theoretical family rather than a
reproduced same-task algorithm.

### 3.4 GHSA process and temporal interpretation

The MSR 2026 GHSA review-pipeline study characterizes reviewed and unreviewed
advisories, two review-latency regimes, and the relationship between advisory
origin and review timing, with released data and analysis code. This evidence
helps explain why publication dates across sources may encode different
processes. We use this study to interpret date discrepancies, while field
correctness and temporal generalization remain outside the evidence supplied by
our snapshot.

### 3.5 Public data and repair-link resources

VulZoo aggregates multiple vulnerability-intelligence sources; CVEfixes links
CVEs to fixes and code; VFCFinder pairs advisories with candidate patches; and
data-quality studies audit vulnerability datasets and their construction. These
resources support aggregation, repair linkage, and quality auditing. They do not
provide same-contract NVD--GHSA maintenance-action labels or an independent
correctness oracle. They are cited as related resources and have not been run as
baselines on the frozen corpus.

### 3.6 Positioning summary

Across the audited literature, discrepancy detection, metadata-quality audit,
attribute generation, affected-version benchmarking, and human deferral are
established but separate tasks. Our task contract combines four structured
fields, a maintenance-action vocabulary, two independent action-first/reason-
second trained-analyst passes, and three frozen routing strategies. RQ3 tests
whether this combined contract supports analyst-consistent strategy
differentiation or exposes a decision boundary.

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
references, while `always_manual` and `abstain_all` define extreme
manual-routing cases.

### 4.3 Reproducibility and sampling use

The label-free analyzer and independent verifier bind the field view, strategy
implementation, counts, and sampling capacity. Their agreement establishes
mechanical reproducibility of the deterministic outputs; semantic validity lies
outside this check. We used the output census to determine whether a fixed
analyst sample could contain strategy-disagreement and shared-no-manual cases
without changing the frozen study objective.

## 5. Analyst-Bounded Validation Protocol

### 5.1 Analyst role and bounded calibration

The protocol specifies two independent doctoral students trained as analysts
for this study, denoted Reviewer A and Reviewer B in the artifacts. It requires
independent work without AI assistance. The construct is trained-analyst
judgment; practitioner behavior is outside its scope.

V3.1 contains 20 calibration-1 cases, a CVE-disjoint 20-case calibration-2
reserve, and 120 formal cases. Calibration-2 is opened only if calibration-1
action agreement is below 0.60 or the guideline changes materially. A second
action agreement below 0.60 terminates formal distribution. The formal
allocation is 50 severity, 50 affected-version, 10 publication-date, and 10
reference cases. All cases are unique within phases, and phase CVE sets are
pairwise disjoint.

### 5.2 Action first, reason second

Each analyst first assigns an action using the visible record pair and allowed
context. The return is validated and the action stage is hash-locked before any
reason packet is released. Only then does the analyst assign `EQ`, `RD`, `INC`,
`TD`, `FC`, or `uncertain`. This ordering prevents the project's taxonomy from
directly defining the action used to evaluate routing utility. It does not
eliminate all anchoring: the same person sees the same case twice, so
same-analyst action--reason association is treated as an upper bound.

### 5.3 Blinding and file governance

Analyst-visible objects use recursive allowlists. Strategy outputs,
deterministic statuses, selection cells, weights, AI candidates, prior reviews,
the other analyst's materials, and future-stage packets are excluded. URLs can
reveal source identity, so the protocol is strategy-blinded but not perfectly
source-blinded.

### 5.4 Formal estimands and stop rules

Pre-adjudication analysis reports analyst-specific raw action agreement,
nominal Krippendorff alpha, uncertainty, disagreement matrices, and reason
agreement as RQ3 validity diagnostics. Cross-analyst action--reason association
is primary; same-analyst association is secondary. RQ3 uses paired action
matches on strategy-disagreement rows, exact McNemar discordance, blocked
intervals, manual-route coverage, abstention, and design-weighted sensitivity.
Paired comparisons remain analyst-specific.

The formal set also contains a fixed 34-case shared-no-manual audit (15 severity
and 19 affected-version cases). An analyst conflict-escalation action on one of
these cases can reveal a shared miss; the resulting inference is limited to the
34 sampled cases. Branch P requires, for each analyst, at least 29 conflict
actions, no lower type-first manual coverage, a one-sided simple-only-loss upper
bound below `delta_manual=0.10`, the frozen paired direction, and no
contradictory systematic failure. If either analyst fails, Branch B is selected.

### 5.5 Adjudication

Author adjudication, if performed, is strategy-blinded, secondary, and reported
after the pre-adjudication results. A sensitivity analysis excludes every
adjudicated case. Adjudication cannot be used to repair low independent
agreement or reverse a failed strategy gate.

## 6. Results

### 6.1 RQ1 -- Deterministic discrepancy landscape

| Field | EQ | RD | INC | TD | FC | Total |
|---|---:|---:|---:|---:|---:|---:|
| Severity | 3,106 | 3,178 | 33 | 0 | 1,749 | 8,066 |
| Affected versions | 425 | 3,936 | 3,054 | 0 | 651 | 8,066 |
| Publication date | 0 | 6,169 | 0 | 1,897 | 0 | 8,066 |
| References | 0 | 300 | 7,763 | 0 | 3 | 8,066 |

These values are generated from the same label-free census as
`paper/jss/latex/table_rq1_status_counts.tex`.

The deterministic census contains 8,066 observations for each of the four
fields. Severity was classified as 3,106 equivalent, 3,178 representation
discrepancy, 33 incomplete, and 1,749 factual conflict. Affected versions
contained 425 equivalent, 3,936 representation discrepancy, 3,054 incomplete,
and 651 factual conflict instances. Publication date contained 6,169
representation and 1,897 temporal discrepancies. References contained 300
representation discrepancies, 7,763 incomplete instances, and three factual
conflicts. These counts are rule outputs, not verified factual labels or
database-quality measurements.

**Answer to RQ1.** Under the frozen field rules, the status distribution is
field-specific. Representation differences dominate severity and publication
date, while incomplete values dominate references; affected versions are
distributed across representation, incomplete, equivalent, and conflict
statuses. These rule-based counts describe the frozen corpus and field
contracts.

### 6.2 RQ2 -- Deterministic routing comparison

| Strategy | No action | Enrich | Wait | Conflict | Abstain | Manual total | All |
|---|---:|---:|---:|---:|---:|---:|---:|
| Field-aware simple | 15,182 | 12,009 | 1,897 | 1,780 | 1,396 | 3,176 | 32,264 |
| Type-first current | 17,114 | 10,850 | 1,897 | 2,403 | 0 | 2,403 | 32,264 |
| Type-first abstention-aware | 15,465 | 10,776 | 1,897 | 1,706 | 2,420 | 4,126 | 32,264 |

| Strategy pair | Severity | Affected versions | Publication date | References | Total |
|---|---:|---:|---:|---:|---:|
| Simple vs current | 5 | 2,247 | 0 | 303 | 2,555 |
| Simple vs abstention-aware | 263 | 1,766 | 0 | 303 | 2,332 |
| Current vs abstention-aware | 258 | 2,159 | 0 | 3 | 2,420 |

The current type-first strategy routes 2,403 instances manually, all as conflict
escalations under its frozen mapping. The field-aware and abstention-aware
strategies route 3,176 and 4,126 instances manually, respectively. These counts
describe policy outputs; they do not identify a correct strategy.

The strong field-aware and abstention-aware type-first strategies made different
actions on 2,332 instances: 263 severity, 1,766 affected-version, zero
publication-date, and 303 reference instances. Across the complete corpus, the
abstention-aware strategy produced 1,706 conflict escalations versus 1,780 for
the strong comparator, a difference of -74. When abstentions were also counted
as manual routes, the corresponding totals were 4,126 and 3,176, a difference
of +950. The two deterministic summaries therefore move in opposite directions
and define a queue-allocation trade-off.

**Answer to RQ2.** The frozen strategies allocate the same field instances
differently, with most disagreement concentrated in affected versions and none
between the two reported strategies for publication date. A smaller conflict
queue coexists with a larger total manual route once abstention is counted.
The analysis measures routing allocations; labor, safety, and operational
utility remain unobserved.

### 6.3 RQ3 -- Analyst-bounded validation

**[REAL-HUMAN RESULTS PLACEHOLDER -- DO NOT PRESELECT A RESULT BRANCH OR FILL
WITH AI/SYNTHETIC DATA]**

Required content after valid E08/E09 returns:

- analyst A and B action distributions, including abstain;
- raw action agreement and nominal Krippendorff alpha overall and by field as
  validity diagnostics;
- reason distributions, uncertainty, disagreement matrices, cross-analyst
  action--reason association, and the same-analyst upper bound;
- the calibration path actually used and any pre-formal guideline diff;
- paired action-match differences and exact discordance for each analyst;
- agreement controls separated from policy-disagreement rows;
- conflict queue, abstention, and total manual-route coverage;
- the 34-case shared-no-manual audit outcome with a sample-conditional boundary;
- whether each analyst independently cleared the 25/29 event thresholds and
  `delta_manual=0.10` gate;
- design-weighted sensitivity, effective sample size, and adjudication-exclusion
  sensitivity;
- explicit retention of failed fields, uncertain outcomes, disagreements, and
  systematic field-specific failure candidates.

**Branch P template:** use only if both analysts clear every frozen positive
gate and support the same direction. State the result for this sample and these
trained analysts; do not claim human gold, practitioner consensus, time savings,
deployment safety, or universal superiority.

**Branch B template:** use if calibration terminates or a reliability, paired-
direction, event-floor, coverage, or manual-loss gate fails. Report that the
tested deterministic strategies did not support stable analyst-consistent
differentiation under the frozen contract, then identify the observed boundary
without changing fields, cases, strategies, thresholds, or labels.

## 7. Discussion

### 7.1 What RQ1 and RQ2 already establish

RQ1 establishes the snapshot-bounded discrepancy landscape. RQ2 shows that a
smaller conflict queue can coexist with a larger total manual route once
abstention is counted. Reporting both quantities prevents abstentions from being
omitted from manual-route accounting.

### 7.2 Interpretation under the positive branch

**[CONDITIONAL]** If both analysts clear the frozen gates, interpret the result
as a bounded comparison of routing strategies under independent trained-analyst
actions. Discuss which fields carry the signal and whether abstention changes
coverage as intended. The observed outcomes concern action alignment and
manual-route coverage rather than source correctness or maintenance effort.

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
logs of production curator behavior. The analysts are trained for this study
rather than practitioners. Action-first ordering reduces taxonomy circularity
but does not eliminate repeated-case anchoring. URLs may reveal source identity. We
report uncertainty and pre-adjudication agreement, and a low calibration or
formal reliability result terminates positive claims.

**Internal validity.** The deterministic field rules can be wrong even when
their implementation is reproducible. Sampling is stratified around strategy
comparison and includes a fixed shared-no-manual audit; it is not an unqualified
random sample of all instances. Strategies, sampling cells, thresholds, and
analyses were frozen before human exposure. Analyst-specific results and exact
paired comparisons reduce, but do not remove, dependence on the chosen loss and
action contract.

**Conclusion validity.** A limited number of analyst conflict-escalation actions
may make Branch P statistically unidentifiable. The frozen 25/29 floors and one-sided
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
independent mechanical verifiers bind files and computations. Their scope is
mechanical reproducibility. Real returns may contain private or sensitive
analyst information; public artifacts must separate anonymized analysis data
from analyst-private materials and comply with the final author and
institutional disposition.

## 9. Conclusion

**[WITHHELD PENDING VALID RQ3 RESULTS AND BRANCH SELECTION]**

The final conclusion will restate the snapshot-bounded RQ1/RQ2 findings and then
report either the analyst-consistent Branch P result or the preserved Branch B
boundary for RQ3. Its interpretation will remain within the scope defined in
Section 8.

## References

The checked BibTeX source is `paper/jss/latex/references.bib`. Claim-level source
scope and the one abstract/metadata-only item are recorded in
`paper/jss/CITATION_EVIDENCE_MAP_20260826.md`. The LaTeX build validates
citation-to-reference closure; the final public dataset and software citations
remain conditional on the author-approved archive and persistent identifiers.

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
