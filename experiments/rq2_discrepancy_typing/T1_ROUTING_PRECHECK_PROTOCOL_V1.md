# T1 Routing Precheck Protocol V1

Protocol ID: vuln-adj-jss-t1-routing-precheck-v1

Status: FROZEN_BEFORE_ANY_REAL_HUMAN_LABEL

Freeze date: 2026-08-25

## 1. Purpose

This protocol defines a label-free gate before any smaller V3 human packet is
created or distributed. It asks whether the proposed field-aware simple policy
and the current type-first policy produce enough different actions for a
120-row dual-human comparison to be mechanically identifiable.

The precheck does not use annotation outcomes. It cannot establish that a
policy is correct, superior, safer, more efficient, or ready for submission.
It does not authorize distribution of the existing V2 packets.

## 2. Frozen input and scope

Input:

- data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl
- expected rows: 8,066
- SHA-256:
  c4bb405399bd0050c206b63ece95771c4f566a9a3968f123a16cf02a3b5cc3a2

Fields:

- severity
- affected_versions
- published
- references

The supplementary cwe_ids field is excluded from the human-budget and routing
precheck. The unit is one CVE-field instance. The full census therefore has
32,264 field instances.

## 3. Frozen action vocabulary

Every policy returns exactly one of:

- no_action: the supplied field values require no maintenance action under the
  policy;
- enrich_record: a routine completeness or evidence-enrichment path, not a
  factual-conflict claim;
- wait_for_sync: a timing/freshness path;
- conflict_escalation: send to factual-conflict review;
- abstain: the policy does not support an automated route and preserves the
  case for specialist review.

Conflict-queue burden counts conflict_escalation only. Total manual-review
burden counts conflict_escalation plus abstain. Both must be reported. A lower
conflict queue cannot be described as lower total human workload if abstention
offsets the reduction.

## 4. Frozen policies

### 4.1 Reference arms

binary_observed_non_equal compares the two values retained in the frozen field
view before higher-order semantic typing. It is not claimed to recover every
byte of the original upstream record.

binary_canonical_non_equal compares canonical severity labels, parsed
timestamps, canonical reference URL sets, and effective affected-version span
sets.

Both binary arms return no_action for equality and conflict_escalation for
non-equality. They are lower-bound/reference arms, not the primary practical
comparator.

always_manual and abstain_all are boundary arms.

### 4.2 Primary simple comparator

field_aware_simple_v1 is a frozen strong simple heuristic, not a claim about
observed maintainer practice.

- severity: equal canonical labels produce no_action; a one-sided value
  produces enrich_record; different known canonical labels produce
  conflict_escalation; an uncanonicalizable comparison produces abstain.
- published: same calendar date produces no_action; a one-sided value produces
  enrich_record; different parseable dates produce wait_for_sync; an
  unparseable comparison produces abstain.
- references: equal canonical URL sets produce no_action; every other set
  difference produces enrich_record. A reference-set difference is not treated
  as a factual conflict by this policy.
- affected_versions: equal effective span sets produce no_action; a one-sided
  or strict-subset span set produces enrich_record; non-comparable package keys
  or unparseable intervals produce abstain; clearly disjoint comparable
  intervals produce conflict_escalation; overlapping non-subset intervals
  produce enrich_record.

Package comparability is deliberately simple: lower-case the final package
component after a colon or slash, normalize non-alphanumeric separators to a
hyphen, and require at least one exact key shared by both sources. Failure to
establish comparability is abstention, not proof that packages differ.

### 4.3 Type-first arms

type_first_current_v1 maps the current deterministic status:

- equivalent and representation_discrepancy to no_action;
- incomplete to enrich_record;
- temporal_discrepancy to wait_for_sync;
- factual_conflict to conflict_escalation.

type_first_abstention_v1 is the primary candidate. It uses the same mapping but
abstains at frozen rule-limit boundaries:

- severity factual conflicts with different explicit CVSS vector versions;
- unparseable published factual conflicts;
- disjoint-reference factual conflicts;
- affected-version comparisons whose two populated sides fail the simple
  package-comparability gate;
- affected-version factual conflicts whose intervals cannot be parsed.

These abstention rules are conservative rule limitations. They are not human
truth and cannot be tuned after human outcomes.

Primary comparison:

- first: field_aware_simple_v1
- second: type_first_abstention_v1

## 5. Full-census outputs

The analyzer must report:

- deterministic status counts by field;
- action counts for every policy and field;
- pairwise action-disagreement counts;
- for the primary comparison, action, conflict-queue, and total-manual-review
  disagreement by field and deterministic status;
- corpus conflict-queue and total-manual-review policy outputs;
- explicit claim-boundary flags showing that no human labels are used.

Policy-output burden is not an error count. An escalation becomes unnecessary,
or a non-escalation becomes a miss, only after independent human action labels
exist.

## 6. Planned V3 capacity calculation

The precheck evaluates the previously proposed formal budget without creating
or exposing a packet:

- severity: 50
- affected_versions: 50
- published: 10
- references: 10
- total formal rows: 120

Calibration rows are outside this calculation. For each field and outcome, the
maximum sampled disagreement capacity is the smaller of the formal field
budget and the full-census policy-disagreement count.

The exact paired-test calculation is conditional on effective discordance:
the human action must match one policy and not the other. A policy prediction
difference can match neither human action, so maximum capacity is not realized
power or an expected effect.

Two-sided conditional exact McNemar alpha is fixed at 0.05. The analyzer also
reports the minimum effective discordant rows needed for 0.80 power when the
candidate wins 0.70, 0.80, or 0.90 of effective discordances. These are
sensitivity calculations, not observed or preregistered effects.

## 7. Outcome-independent precheck gates

All gates below must pass for CONDITIONAL_GO_FOR_V3_PACKET_DESIGN:

1. Input has no human labels.
2. The primary policies differ on at least the minimum number of rows that
   could permit any two-sided exact rejection at alpha 0.05.
3. At least two fields have that much action-disagreement capacity under the
   proposed field budgets.
4. At least one efficacy field, severity or affected_versions, has that much
   total-manual-review disagreement capacity.
5. The total proposed sample has at least the conditional capacity required
   for 0.80 exact power if type-first wins 0.80 of effective action
   discordances.

Passing means only that a V3 comparison can be designed. It does not mean the
effect will be present, that human actions will be determinate, or that the
candidate will win.

If any gate fails, the decision is
NO_GO_FOR_POSITIVE_ROUTING_V3_UNDER_CURRENT_POLICIES. Do not repair a failure
by looking at human outcomes, renaming the comparator, dropping a field, or
sampling only favorable cases.

## 8. Positive, negative, and neutral next actions

If the precheck passes:

- write a separate V3 human protocol;
- retain V2 unchanged as historical prepare-only material;
- sample without human outcomes using field, deterministic status, and frozen
  policy disagreement;
- keep a probability-oriented construct layer as well as a
  disagreement-enriched paired layer;
- distribute nothing until reviewer roles, guideline, ethics/compensation, and
  packet hashes are complete.

If it fails because policies are equivalent or statistically unidentifiable:

- stop the positive routing route;
- retain the full-census result as a boundary finding;
- do not spend the human budget to search for a positive effect.

If it passes mechanically but type-first has no lower conflict queue or hides
the same burden in abstention:

- a human action-accuracy comparison may still be run if independently
  justified;
- total-workload reduction is not an allowed claim;
- the framing must emphasize action specificity, safety, or failure boundary
  rather than efficiency.

## 9. Claim ceiling

Regardless of the precheck result, it does not support:

- human-gold labels or reviewer agreement;
- taxonomy accuracy, action accuracy, conflict recall, or unnecessary
  escalation;
- policy superiority or non-inferiority;
- saved time, reduced cognitive effort, or reduced total human workload;
- maintainer behavior or operational deployment;
- cross-source, temporal, or population-wide generalization;
- submission readiness or acceptance likelihood.

## 10. Required artifacts

- this frozen protocol and its hash;
- analyze_t1_routing_precheck.py;
- verify_t1_routing_precheck.py;
- unit tests for policy boundaries and exact-test calculations;
- analysis.json;
- analysis.md;
- manifest.json binding input, protocol, analyzer, verifier, and outputs.

The independent verifier must recompute policy actions and gates directly from
the frozen field view without importing the analyzer implementation.
