# Submission Blockers

Current decision: `NO_GO_FOR_SUBMISSION`.

The V3.1 label-free decision is only
`GO_FREEZE_V3_1_WITH_DELTA_0_10_AND_N29`. It authorizes a prepare-only
protocol and analysis implementation, not packet distribution, human-backed
claims, or submission.

| Class | Item | Required by | Current evidence or status | Owner | Blocks submission? |
|---|---|---|---|---|---|
| Human governance | Two real independent trained analysts | RQ2/RQ3 human claims | Two doctoral students selected as intended trained analysts; practitioner expertise is not claimed. Private identity, doctoral-status, experience, compensation, conflict, consent, and independence evidence remains unsigned/unverified | Authors | Yes |
| Human governance | Ethics/recruitment determination and author distribution approval | Packet distribution | Onboarding forms, hash-only approval record, action-only builder, and independent validator exist. Readiness is `BLOCKED` with 31 fine-grained unmet checks; V3.1 preparation manifest remains `distribution_allowed=false` | Authors/institution | Yes |
| Scientific | V3.1 action-first/reason-second construct validation | RQ2 | Prepare-only calibration-1 20, calibration-2 reserve 20, and formal 120 packets validate; stage locks empty; human labels 0 | Authors and two reviewers | Yes |
| Scientific | Frozen return validators and evaluator | Outcome-independent RQ2/RQ3 analysis | Implemented, hash-bound, unit-tested, and exercised end to end with temporary synthetic labels; this is mechanical readiness only | Authors | No longer a blocker |
| Scientific | Shared no-manual-route falsification audit | Positive routing-safety framing | Fixed 34-case derived audit exists; no human labels; its 8.43% zero-event bound would be sample-conditional, not a population bound | Authors and two reviewers | Yes for positive framing |
| Scientific | Human-backed three-policy routing frontier | Central RQ3 framing | Label-free census only; no policy correctness, match, safety, or utility result | Authors | Yes |
| Scientific | T3 human-backed adjudication comparison, if adjudication remains core | Positive adjudication-method claim | Current affected-version result is a non-human no-go | Authors | Conditional: yes if core, otherwise remove claim |
| Scientific | Temporal cohort, if future generalization remains a claim | Temporal-validity claim | Strict event-time cohort unavailable | External data availability | Conditional: remove claim or wait |
| Manuscript | JSS manuscript source | Complete paper | Brief, ledgers, and S2 candidate plan only | Authors | Yes |
| Manuscript | Closest-work synthesis in the manuscript | Novelty/positioning | Literature inventory and per-paper notes exist; manuscript synthesis not written | Authors | Yes |
| Manuscript | COSE-to-JSS compression and evidence selection | Coherent JSS paper | Historical COSE draft remains a long, mixed-provenance evidence source | Authors | Yes |
| Format/artifact | Current JSS guide, template, declarations, and artifact checks | Venue compliance | Complete current submission requirements not frozen | Authors | Yes at S6/S7 |
| Author metadata | Title, author order, affiliations, corresponding author, funding, conflicts, CRediT, data/code, and AI-use statements | Submission form/manuscript | Unresolved placeholders | Authors | Yes |
| External action | Upload and submit | Submission | Not requested and not performed | Corresponding author | Yes |

## Earliest admissible path

1. Have the two selected doctoral students complete private onboarding forms;
   record their non-identifying qualification summaries and signed-record hashes,
   the ethics/recruitment disposition, and named-author approval. Then rerun the
   existing revision-R1 gate scoped to reviewer A/B, calibration-1, action only.
2. Run independent calibration-1 actions, validate and lock them, then release
   and lock calibration-1 reasons.
3. Record the guideline diff. Use the presealed, CVE-disjoint calibration-2
   reserve only if raw action agreement is below 0.60 or the guideline changes
   materially. A second action agreement below 0.60 terminates formal
   distribution.
4. If calibration clears, run independent formal actions, lock them, then
   formal reasons.
5. Freeze pre-adjudication results and apply reviewer-specific reliability,
   exact paired efficiency, 34-case shared-miss, and `delta_manual=0.10`
   safety gates. Preserve abstain, uncertain, disagreement, and failed fields.
6. Require at least 29 human conflict actions per reviewer and both reviewers'
   safety passes for positive efficiency-safety framing. Fewer than 25 for
   either reviewer makes conflict recall interval-only.
7. Run blinded author adjudication only as secondary sensitivity and recompute
   after excluding all adjudicated cases.
8. Choose positive-frontier, decision-ambiguity, or negative framing; then
   draft and validate the JSS manuscript.
9. Recheck venue, artifact, metadata, and author approval gates before any
   external submission action.
