# T1/T2 Action-First Annotation Guideline V3.1

Status: `DRAFT_NOT_APPROVED_FOR_DISTRIBUTION`

Protocol: `vuln-adj-jss-t1-human-validation-v3.1`

This guideline is for two trained analysts reviewing frozen, left/right-masked
NVD-GHSA field pairs. It defines judgments; it is not evidence that annotation
has started or that any answer is correct.

## Stage A: maintenance action

Question: **If these two displayed values must be reconciled into a maintained
vulnerability record, what should the analyst do next using only the supplied
context?**

Choose exactly one action before seeing or entering a discrepancy reason.

### `no_action`

The values are compatible for the maintenance purpose. Straightforward
normalization may make them identical, but no information must be added and no
source investigation is needed.

### `enrich_record`

The values are compatible but one side supplies useful information absent from
the other. Merge or add the non-conflicting information. Do not use this when
package identity or version ordering is too unclear to establish compatibility.

### `wait_for_sync`

The difference is plausibly caused by publication or update timing and should
be checked again after propagation. This is not a generic unsure option and is
expected mainly for publication dates.

### `conflict_escalation`

The values cannot both be accepted for the same comparable field scope after
ordinary normalization. A human must inspect evidence or decide which value to
retain. Different CVSS versions, packages, or incomparable scopes are not
automatically conflicts; use `abstain` when comparability is not established.

### `abstain`

The supplied context is insufficient to choose a safe maintenance action, or
the sides may not describe directly comparable scopes. State what is missing.
Abstention is a completed answer, not an error.

Required Stage-A fields:

- `action_label`: exactly one allowed action;
- `action_rationale`: one or two concrete sentences;
- `action_uncertainty`: missing or ambiguous context, if any;
- `reviewer_notes`: optional.

Return the whole Stage-A packet for validation and hashing. Do not revise an
action after the corresponding reason packet is released.

## Stage B: discrepancy reason

Stage B starts only after both reviewers' Stage-A returns for that phase are
locked. The reason packet deliberately does not display the earlier action.

Choose exactly one reason.

### `equivalent`

Both sides express the same field meaning after straightforward normalization.

### `representation_discrepancy`

Raw values or schemas differ, but they are compatible descriptions of the same
fact, such as canonical severity synonyms, timestamp formatting, or equivalent
version endpoints.

### `incomplete`

One side is missing information or is a compatible strict subset of the other.

### `temporal_discrepancy`

Publication or update timing best explains the difference. Do not assign it to
every unequal date without considering what the timestamps represent.

### `factual_conflict`

Both sides make incompatible claims about a comparable field scope, and the
difference is not adequately explained by representation, missing coverage, or
timing.

### `uncertain`

The supplied values or context are insufficient to select one of the five
substantive reasons reliably. State what blocks the decision.

Required Stage-B fields:

- `reason_label`: exactly one allowed reason;
- `reason_rationale`: one or two concrete sentences;
- `reason_uncertainty`: missing or ambiguous context, if any;
- `reviewer_notes`: optional.

## Field-specific checks

### Severity

Compare canonical labels, scores, vectors, CVSS versions, and stated scope. A
label difference is not necessarily a factual conflict when vectors use
different CVSS versions or incomparable scoring assumptions.

### Affected versions

Check package identity and ecosystem before comparing intervals. Distinguish
equivalent syntax, compatible subset/enrichment, disjoint comparable ranges,
and unparseable or cross-package cases. Incomparable packages normally require
abstention/uncertainty rather than forced conflict.

### Published

Distinguish formatting or timezone precision from real publication/update lag.
Different source publication dates may legitimately coexist. Choose
`wait_for_sync` only when a later propagation check is the appropriate action.

### References

Compare resource identity and evidentiary role, not only raw URL sets.
Complementary references can justify enrichment. Opaque, redirecting, or
unavailable resources may require abstention/uncertainty.

## Calibration and revision

- Calibration cases are practice material and never enter formal endpoints.
- Complete each calibration stage independently before discussion.
- Discuss disagreements only after both reviewers' reason returns are locked.
- The author records every guideline change and whether it is material.
- If calibration-2 is triggered, use only the newly frozen guideline and the
  presealed calibration-2 reserve.
- Do not open formal packets until the protocol's calibration gate is cleared.

## Independence and evidence restrictions

- Use only the frozen packet context during the primary pass.
- Do not browse live NVD, GHSA, vendor, repository, or search pages.
- Do not infer source identity from left/right position. URLs may reveal it, but
  source reputation alone is not a decision rule.
- Do not consult the other reviewer, deterministic labels, policy outputs,
  AI/model results, or prior consensus before both independent passes lock.
- Difficult cases remain. Use `abstain` or `uncertain`; never leave an
  intended answer blank.
