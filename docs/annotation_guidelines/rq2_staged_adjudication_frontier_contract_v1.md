# RQ2 Staged Adjudication Frontier Contract v1

## Purpose

This is a post-hoc, read-only audit of the already completed RQ2 typing chain. It
reconstructs request provenance and the marginal candidate coverage of reviewer
A/B, reviewer C, and evidence reviewers D/E. It does not create or alter a
label.

## Fixed inputs

- the sealed 1,250-row RQ2 holdout and its A/B request logs and merge summary;
- the sealed 103-row reviewer-C request log and merge summary;
- the sealed 37-row D/E request logs and merge summary;
- the final baseline-to-candidate agreement artifact;
- the three-row residual non-affected diagnostic.

All inputs are consumed from the existing repository snapshot. The analyzer
must hash every input in its result manifest. Existing request logs are
immutable; provenance gaps are represented in a new audit artifact rather than
backfilled into the old logs.

## Request provenance rules

1. A request payload identity is the ordered tuple of `sample_id` values in its
   `items` list.
2. A successful response identity is the ordered tuple in `sample_ids`.
3. For each exact payload identity, excess request attempts are
   `request_count - response_success_count` when positive.
4. If duplicate identical requests share fewer success events, the specific
   failed attempt is unresolved. The audit may report the candidate source
   lines but must not invent which attempt failed or an error reason.
5. A gap payload is outcome-complete only when every requested sample appears
   in some successful response in the same reviewer log. Split retries may
   establish row completion but do not repair attempt-level provenance.
6. Request-row attempts count every item in every request, including retries.
   Successful reviewer-row decisions count every item in successful responses.
7. Token usage is summed only from recorded `response_success` events and must
   be named recorded-success usage. No token usage is imputed for missing
   attempts.

## Frontier rules

- A/B contributes only strict dual consensus.
- Reviewer C contributes only rows added by the sealed tiebreak merge.
- D/E contributes only evidence-qualified strict rows added by the sealed
  evidence-secondary merge.
- Marginal yield is reported both per selected row and per successful
  reviewer-row decision. These are operational diagnostics, not accuracy.
- The fixed combined-coverage target remains `0.982`, which requires at least
  1,228 of 1,250 candidate rows. Thresholds may not be relaxed after reading
  the result.
- Targeted residual and graph diagnostics may be listed as post-frontier
  evidence, but rows with promotion disabled contribute zero candidate rows.
- Non-human candidate coverage never reduces the 1,250-row real-person review
  requirement.

## Decision rule

Set `stop_same_model_escalation=true` only if all of the following are observed
in the fixed artifacts:

- reviewer C fails its sealed advancement gate;
- D/E fails its sealed advancement gate;
- combined candidate coverage remains below `0.982`;
- the targeted residual diagnostic promotes zero rows.

This rule supports stopping further same-model review on the revealed cohort.
It does not predict the yield of real reviewers or a future independent
snapshot.

## Claim boundary

- `post_hoc=true`
- `label_is_human=false`
- `eligible_for_human_gold_claim=false`
- `accuracy_claim_allowed=false`
- `production_switch_allowed=false`
- `existing_logs_mutated=false`

The next value-bearing paths after a stop decision are real-person review under
the prepared packet or a later independently collected confirmation cohort.
