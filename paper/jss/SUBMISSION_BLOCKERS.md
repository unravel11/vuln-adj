# Submission Blockers

Current decision: `NO_GO_FOR_SUBMISSION`.

The V3.1 label-free decision is only
`GO_FREEZE_V3_1_WITH_DELTA_0_10_AND_N29`. It authorizes a prepare-only
protocol and analysis implementation, not packet distribution, human-backed
claims, or submission.

| Class | Item | Required by | Current evidence or status | Owner | Blocks submission? |
|---|---|---|---|---|---|
| Human governance | Two real independent trained analysts | RQ2/RQ3 human claims | Author attests that two different doctoral students will work independently without AI; paper framing is trained analysts, not practitioners. Codex did not independently verify the author-side facts | Authors | No for packet distribution; accurate reporting remains required |
| Human governance | Participation/conflict/compensation, applicable ethics requirements, and author distribution approval | Packet distribution | Minimal R2 author attestation records these conditions as handled; readiness is `READY` and reviewer-scoped action bundles validate | Authors/institution | No under the author's attestation |
| Scientific | V3.1 action-first/reason-second construct validation | RQ2 | Prepare-only calibration-1 20, calibration-2 reserve 20, and formal 120 packets validate; stage locks empty; human labels 0 | Authors and two reviewers | Yes |
| Scientific | Frozen return validators and evaluator | Outcome-independent RQ2/RQ3 analysis | Implemented, hash-bound, unit-tested, and exercised end to end with temporary synthetic labels; this is mechanical readiness only | Authors | No longer a blocker |
| Scientific | Shared no-manual-route falsification audit | Positive routing-safety framing | Fixed 34-case derived audit exists; no human labels; its 8.43% zero-event bound would be sample-conditional, not a population bound | Authors and two reviewers | Yes for positive framing |
| Scientific | Human-backed three-policy routing frontier | Central RQ3 framing | Label-free census only; no policy correctness, match, safety, or utility result | Authors | Yes |
| Scientific | T3 human-backed adjudication comparison, if adjudication remains core | Positive adjudication-method claim | Current affected-version result is a non-human no-go | Authors | Conditional: yes if core, otherwise remove claim |
| Scientific | Temporal cohort, if future generalization remains a claim | Temporal-validity claim | Strict event-time cohort unavailable | External data availability | Conditional: remove claim or wait |
| Manuscript | JSS manuscript source | Complete paper | Result-neutral title, thesis, RQ1--RQ3, exactly three contribution ceilings, and Branch P/B contract were author locked at S2 on 2026-08-26; the English zero draft covers Introduction, Related Work, corpus/RQ1, three strategies, V3.1, Discussion branches, and threats, but its prose is not author approved and RQ2/RQ3 remain placeholders | Authors | Yes until human results and author revision |
| Manuscript | Closest-work synthesis in the manuscript | Novelty/positioning | Zero draft and `docs/RELATED_WORK_AND_BASELINE_AUDIT_20260825.md` include the closest intersection, public resources, same-task baselines, and overlap risks; final citation reconciliation remains | Authors | No for zero-draft preparation; yes for final manuscript integrity |
| Manuscript | COSE-to-JSS compression and evidence selection | Coherent JSS paper | Historical COSE draft remains a long, mixed-provenance evidence source | Authors | Yes |
| Format/artifact | Current JSS guide, template, declarations, and artifact checks | Venue compliance | Official Guide for Authors checked 2026-08-25 and checklist recorded; Markdown is not submission source, Elsevier template is not instantiated, author-anonymization mode requires live recheck, and no final artifact exists | Authors | Yes at S6/S7 |
| Author metadata | Title, author order, affiliations, corresponding author, funding, conflicts, CRediT, data/code, and AI-use statements | Submission form/manuscript | Unresolved placeholders | Authors | Yes |
| External action | Upload and submit | Submission | Not requested and not performed | Corresponding author | Yes |

## Earliest admissible path

1. Deliver each validated R2 calibration-1 action bundle only to its named
   reviewer; preserve independent work and do not release reason or future-stage
   packets.
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
