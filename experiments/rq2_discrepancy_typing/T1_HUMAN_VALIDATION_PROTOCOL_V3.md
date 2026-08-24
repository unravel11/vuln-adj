# T1/T2 Action-First Human Validation Protocol V3

Protocol ID: `vuln-adj-jss-t1-human-validation-v3`

Status: `FROZEN_FOR_PREPARATION_BEFORE_HUMAN_EXPOSURE`

Freeze date: 2026-08-25

Distribution status: `BLOCKED`

This protocol replaces V2 only for the active low-human JSS route. V2 remains
an immutable historical prepare-only artifact: it received no human labels and
must not be distributed. V3 was frozen after a label-free census and before any
V3 packet was shown to a reviewer.

## 1. Purpose and claim ceiling

V3 uses one independent human round to answer two linked questions:

1. which maintenance action a trained vulnerability-advisory analyst would
   take for a displayed field-value pair; and
2. which discrepancy reason best explains that pair after the action answer is
   locked.

The study compares a strong field-aware simple policy with two type-first
variants:

- `field_aware_simple_v1`: a strong hand-written comparator, not an observed
  industry-practice claim;
- `type_first_current_v1`: the efficiency candidate without added abstention;
- `type_first_abstention_v1`: the safety candidate with frozen rule-limit
  abstention.

Raw and canonical non-equality are lower-reference arms only. The study does
not measure elapsed maintenance time, staffing cost, adoption, or production
benefit. A routing count is not a workload-reduction result.

The label-free precheck at
`results/jss/t1_routing_precheck_v1/analysis.json` authorizes packet design
only. It establishes neither correctness nor policy superiority.

## 2. Frozen population and fields

Population:
`data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl`

- 8,066 CVE-aligned rows;
- SHA-256:
  `c4bb405399bd0050c206b63ece95771c4f566a9a3968f123a16cf02a3b5cc3a2`;
- four fields: `severity`, `affected_versions`, `published`, and `references`;
- 32,264 field instances before sampling.

V3 excludes `cwe_ids`. That field is outside the routing question and adding it
would dilute the fixed human budget.

## 3. Human budget and frozen sampling design

Two different real trained analysts independently review the same cases.
Human budget is 140 cases per reviewer:

- calibration: 20 cases, five per field;
- formal evaluation: 120 cases;
- formal allocation: severity 50, affected versions 50, published 10, and
  references 10.

Evaluation cases are selected first by stable SHA-256 rank. Calibration cases
are then selected from the remaining population. Calibration never enters a
formal endpoint.

### 3.1 Evaluation cells

Severity, 50 cases:

- 25 `factual_conflict` cases where the simple policy escalates and the safety
  policy abstains;
- all five `representation_discrepancy` cases where the simple policy abstains
  and the safety policy takes no action;
- 20 agreement controls: five each from equivalent, representation,
  incomplete, and factual-conflict strata.

Affected versions, 50 cases:

- 30 policy-disagreement cases: six from each frozen simple-to-safety action
  pair (`abstain->no_action`, `enrich_record->abstain`,
  `enrich_record->conflict_escalation`, `enrich_record->no_action`, and
  `no_action->abstain`);
- 20 agreement controls: five each from equivalent, representation,
  incomplete, and factual-conflict strata.

Published, 10 construct controls:

- five representation discrepancies;
- five temporal discrepancies.

References, 10 cases:

- all three factual-conflict rows;
- four representation discrepancies;
- three incomplete rows.

Every evaluation cell records its population count, selected count, inclusion
probability, and `N_h/n_h` sensitivity weight. The primary comparison is
sample-level and disagreement-focused. Design-weighted population projection
is a sensitivity analysis because several cells are deliberately small.

### 3.2 Calibration construction

Calibration is constructed to expose, without prescribing a human answer:

- every frozen action at least twice across the three main policies;
- every deterministic discrepancy status at least twice; and
- at least two rule-limit cases for which abstention is a plausible answer.

Calibration composition is sealed in the manifest. Reviewers may discuss the
rubric after both independent calibration passes. A guideline change requires
a recorded V3.x amendment and resealing before either reviewer opens formal
evaluation material. Evaluation selection may not be changed in response to
calibration labels.

## 4. Action-first, reason-second collection

Allowed actions:

- `no_action`
- `enrich_record`
- `wait_for_sync`
- `conflict_escalation`
- `abstain`

Allowed reasons:

- `equivalent`
- `representation_discrepancy`
- `incomplete`
- `temporal_discrepancy`
- `factual_conflict`
- `uncertain`

For calibration and evaluation separately:

1. reviewer A and reviewer B independently complete all action packets;
2. the returns are hashed and the stage-lock record is signed;
3. only then are reason packets released;
4. reason packets do not display the reviewer's earlier action;
5. reviewers do not see one another's labels before both reason passes are
   frozen.

The action question is therefore not primed by the reason taxonomy in the data
entry form. Some memory anchoring remains possible and must be reported.

## 5. Human roles and blinding

The paper uses “trained analyst,” not “maintenance practitioner,” unless the
signed role record establishes actual practitioner experience.

Each reviewer must have documented ability to interpret CVE/advisory records,
CVSS or severity, reference evidence, and package/version ranges. IDs alone do
not prove real-human identity or independence.

Reviewer packets omit deterministic status, policy outputs, policy names,
baseline notes, NVD/GHSA source IDs, AI/Codex labels, prior review labels, and
the other reviewer's answers. Left/right source identity is masked. URLs may
still reveal the source and are an explicit blinding limitation. Reviewers use
only frozen packet context during the primary pass; no unlogged live browsing
is allowed.

The resolving author sees disagreements only after both independent passes are
hashed and remains blind to policy outputs during adjudication.

## 6. Primary analyses

Pre-adjudication results are primary.

### 6.1 Construct reliability

Report overall and per field:

- raw action agreement;
- nominal Krippendorff alpha for action;
- raw reason agreement and nominal alpha;
- abstention/uncertain rates;
- complete disagreement matrices.

`abstain` and `uncertain` are completed outcomes and are never deleted.

### 6.2 Routing-policy comparison

On formal policy-disagreement rows, compare each frozen policy action with
reviewer A and reviewer B separately. Report paired match differences and
exact paired tests. A positive policy claim requires the same direction for
both reviewers and a two-sided 95% paired interval excluding zero in the
pre-specified pooled sensitivity analysis. Resampling is blocked by CVE so the
same CVE appearing in multiple field instances is not treated as independent.

Agreement controls estimate failure outside policy-disagreement cells. Report
them separately; do not let numerous easy agreements dominate the main table.

Conflict recall is reported only against independently assigned
`conflict_escalation` actions. “Factual conflict” reasons do not automatically
equal an escalation action.

### 6.3 Reason-to-action relationship

The primary association evidence is cross-reviewer:

- reviewer A action versus reviewer B reason;
- reviewer B action versus reviewer A reason.

Same-reviewer action-versus-reason association is an explicitly labelled upper
bound because the same person supplied both answers. Association is
descriptive and does not establish that the taxonomy caused the action.

### 6.4 Population and burden sensitivity

Apply manifest weights only as a sensitivity analysis. Report Kish effective
sample size and cell-level intervals. “Conflict queue” means only
`conflict_escalation`; “manual-review route” means
`conflict_escalation + abstain`. Neither is called labor cost or saved time.

## 7. Outcome-independent gates and stop rules

- Any missing reviewer identity, independence statement, required ethics
  determination, packet hash, or stage lock blocks distribution or analysis.
- Calibration action raw agreement below 0.60 blocks formal distribution until
  an outcome-independent guideline amendment is frozen. Evaluation cases
  remain unopened and unchanged.
- Formal action raw agreement below 0.60 **or** nominal Krippendorff alpha below
  0.40 forbids a positive routing claim. The result becomes a decision-
  ambiguity study.
- Fewer than 25 human `conflict_escalation` actions across the two independent
  formal passes means conflict recall is interval-only; no arm ranking by
  conflict recall is made.
- A “systematic failure structure” exists only if the same predeclared
  action-pair or reason-pair failure appears in at least two fields and accounts
  for at least 30% of disagreements in each affected field.
- Author adjudication is secondary. Recompute all conclusions after excluding
  every adjudicated case. A claim that disappears is not primary.
- No policy superiority claim is allowed if the two reviewers favor different
  policies on the paired primary endpoint.

Failed rows, fields, disagreements, abstentions, and uncertain reasons remain
in all artifacts. They may not be dropped, replaced, or relabelled to rescue a
route.

## 8. Distribution and execution gates

The generated V3 directory must remain
`PREPARATION_ONLY_NOT_FOR_DISTRIBUTION` until all of the following exist:

1. author-approved, versioned guideline;
2. signed reviewer role and independence record;
3. recorded ethics/recruitment determination;
4. passing packet validator and matching hashes;
5. explicit author distribution approval in a new manifest revision.

The current preparation manifest must keep `distribution_allowed=false`. A
distribution-ready validator is expected to fail until a separate approved
revision is created. No human labels currently exist.
