# JSS S2 Framing Lock Record

> **SUPERSEDED FOR CURRENT FRAMING.** This record preserves the first
> 2026-08-26 S2 lock and its Claude high-effort provenance. After the author
> questioned the prominence of the human study, S2 was reopened and relocked
> under the routing-centric architecture in
> `FRAMING_REBALANCE_LOCK_RECORD_20260826.md`. The title, thesis, RQs, and
> contributions below are historical and must not be used as the current lock.

## Decision

- Date: 2026-08-26 (Asia/Singapore)
- Decision: `SUPERSEDED_ARGUMENT_LOCK`
- Resulting stage: `S2_ARGUMENT_LOCKED`
- Author authorization: the author explicitly asked Codex to start Claude,
  discuss the framing, and decide it directly.
- Scientific effect: none. This record fixes the paper argument and claim
  ceiling; it does not create E08/E09, human gold, policy performance, or
  submission readiness.

## Frozen authority reviewed

- Host: `code-defender`
- Workspace: `/home/xiaoyuliang/code/vuln-adj`
- Branch: `codex/jss-zero-draft-venue-20260825`
- Pre-lock HEAD: `b675128338154d21e90686a4b6a5591ae1ac0110`
- Pre-lock Git state: clean; upstream divergence `0/0`
- Human evidence: zero real-human returns; E08/E09 remain
  `MISSING_OR_UNRESOLVED`

## Claude challenge record

- Claude Code: `2.1.226`
- Model reported by the decisive call: `claude-opus-5`
- Effort: `high`
- Session ID: `ed24b4b7-45d5-4b74-91fd-15925019971c`
- Permissions: read-only planning; only `Read`, `Grep`, and `Glob` allowed;
  edit, write, Bash, and web tools denied
- Whitelist: `AGENTS.md`, the JSS brief/framing/argument/claim/evidence files,
  the closest-work audit/synthesis, and the result-neutral manuscript
- Exclusions: `.env`, private reviewer material, reason, calibration-2, formal
  packets, experiments, repository edits, and web browsing
- Raw local Claude session record at decision time:
  `/home/xiaoyuliang/.claude/projects/-home-xiaoyuliang-code-vuln-adj/ed24b4b7-45d5-4b74-91fd-15925019971c.jsonl`
- Raw-record SHA-256 at decision time:
  `318a67426484cce233ab28dc890b126961baa08863007f090a0c4ea323925adb`

The first Claude turn accepted the exact title, thesis, RQs, three
contributions, dual branches, and `P2_VIABLE_CONDITIONAL` potential, but returned
`DO_NOT_LOCK` because it incorrectly treated S2 as requiring empirical branch
selection. Codex challenged that conflation using the repository's stage
contract: S2 locks a result-neutral argument architecture, while E08/E09 select
Branch P or B later. In the same session, Claude revised its verdict to:

> `LOCK_AS_S2` -- The result-neutral architecture is complete,
> dual-branch-compatible, and does not presuppose human outcomes. All
> human-dependent claims correctly remain `ABSTAIN`.

This model exchange is an advisory stress test, not an independent human review
and not evidence that the scientific claims are true.

## Author-locked title

_When Vulnerability Metadata Differ: A Human-Gated Study of Field-Level Routing
between NVD and GHSA_

## Author-locked one-sentence thesis

For CVE-aligned NVD–GHSA record pairs, comparing a strong field-aware strategy
with type-first efficiency and safety variants reveals a deterministic routing
trade-off whose validity depends on whether two independent trained analysts can
reliably assign maintenance actions before assigning discrepancy reasons.

## Author-locked research questions

- **RQ1 -- Deterministic landscape.** Across 8,066 CVE-aligned NVD–GHSA record
  pairs, how do deterministic field statuses and frozen routing-policy outputs
  distribute for severity, affected versions, publication date, and references?
- **RQ2 -- Analyst decision construct.** To what extent do two independent
  trained analysts agree when assigning maintenance actions and, after action
  lock, discrepancy reasons to the same frozen field pairs, and where do they
  remain uncertain or disagree?
- **RQ3 -- Policy alignment and boundary.** Relative to a strong field-aware
  simple strategy, how do a current type-first strategy and an abstention-aware
  type-first strategy align with each analyst's actions, and what efficiency,
  coverage, abstention, and shared-miss boundaries are observed?

## Exactly three author-locked contributions

1. **Reproducible four-field deterministic census.** A snapshot-bounded census
   of 8,066 CVE-aligned NVD--GHSA record pairs and 32,264 field instances, with
   deterministic field statuses and routing outputs for severity, affected
   versions, publication date, and references. It cannot support database
   quality, ground truth, broader prevalence, causal explanation, or
   correctness.
2. **Three-strategy comparison with explicit efficiency--safety accounting.**
   A frozen comparison among a strong field-aware simple comparator, a
   type-first efficiency arm, and an abstention-aware safety arm. Deterministic
   outputs differ, but E08/E09 are required before any correctness, safety,
   utility, or superiority wording.
3. **Action-first/reason-second dual-analyst protocol with a preserved boundary
   path.** A mechanically frozen V3.1 protocol with recursive allowlist
   blinding, stage locks, and outcome-independent stop rules. Valid returns
   license either a reviewer-consistent routing-frontier result or an empirical
   boundary; before E08/E09 it is not a validated human construct.

The retrospective reconciliation-limit material is supporting discussion
evidence, not a fourth contribution. Human-backed policy alignment or a
boundary result is the result disposition of contributions 2 and 3, not a
pre-result contribution.

## Result branches and L1 disposition

- Selected pre-result framing: one human-gated, result-neutral audit with two
  predeclared result branches; do not select an empirical branch now.
- L1 potential: `P2_VIABLE_CONDITIONAL`.
- Experiment decision: the already frozen V3.1 human process remains the only
  load-bearing `TARGETED_EXPERIMENT`; no additional core experiment is
  authorized or needed before its results.
- Branch P: permitted only if both reviewers clear every frozen reliability,
  paired-direction, event-floor, coverage, and safety gate.
- Branch B: mandatory if any frozen stop condition fails; retain disagreement,
  abstention, uncertainty, shared misses, and failed gates without rescue.

### Framing A/B potential gate

| Dimension | Framing A: human-supported routing frontier | Framing B: empirical decision boundary |
|---|---|---|
| One-sentence result disposition | Both reviewers support the same bounded alignment/coverage trade-off under every frozen gate. | The tested information contract does not yield a stable positive routing conclusion; the failed construct, direction, coverage, safety, or identifiability gate is the result. |
| Direct evidence now | E01, E07B, E07D--E07F for census and design only. | E01, E04--E07F for census, design, and bounded retrospective failure context. |
| Missing load-bearing evidence | E08/E09. | E08/E09 are still required to identify the observed boundary rather than speculate about one. |
| JSS value | Human-gated field-level routing comparison with a strong comparator and explicit abstention accounting. | Reproducible evidence about when deterministic metadata typing fails to identify stable maintenance decisions. |
| Stop rule | Any reviewer-specific gate failure forbids this branch. | Preserve the failing gate and do not rescue the positive branch. |
| Potential | `P2_VIABLE_CONDITIONAL` | `P2_VIABLE_CONDITIONAL` if the observed boundary is reported at its actual scope. |

The selected paper architecture is the shared result-neutral frame above both
columns. It is not a pre-result selection of Framing A or Framing B.

### L1 gate result

| Gate | Status | Basis |
|---|---|---|
| L1-G0 authority and snapshot | `PASS` | Clean authoritative remote, explicit writing branch/HEAD, current ledgers, and historical COSE/V2/V3 lines separated. |
| L1-G1 research questions | `PASS` | The four fields, aligned-pair object, analyst decision unit, and three neutral RQs are explicit. |
| L1-G2 core framing | `PASS` | The title and thesis are result-neutral and share one estimand with the frozen protocol. |
| L1-G3 claim--evidence coverage | `PARTIAL` | RQ1/design claims are supported; all RQ2/RQ3 empirical claims remain `ABSTAIN` on missing E08/E09. |
| L1-G4 contribution distinguishability | `PASS` | The allowed differential is maintenance-action routing with a strong field-aware comparator, action-first judgment, abstention, and a preserved no-go path, not discrepancy detection or affected-version identification. |
| L1-G5 JSS potential | `P2_VIABLE_CONDITIONAL` | A coherent software-maintenance audit exists, but human evidence blocks the empirical contribution and submission. |
| L1-G6 experiment sufficiency | `PARTIAL` | The only load-bearing remaining experiment is the already frozen V3.1 human process; no additional core experiment is justified now. |
| L1-G7 writability | `PARTIAL` | Result-neutral zero draft exists; RQ2/RQ3, abstract, conclusion, and branch-dependent interpretation remain unwritable before E08/E09. |
| L1-G8 stop rule | `PASS` | Both positive and boundary routes, reviewer-specific gates, no-rescue discipline, and S2 reopening rule are explicit. |

L1 experiment decision: `TARGETED_EXPERIMENTS`, limited to the already frozen
V3.1 human process. Human execution is paused by author choice; no new sample,
baseline, policy, threshold, or auxiliary experiment is authorized.

## Explicitly unlocked

- E08/E09 and every RQ2/RQ3 statistic;
- Branch P/B selection and result-dependent headings;
- abstract, conclusion, highlights, and final references;
- placement of the retrospective reconciliation-limit section;
- zero-draft prose approval;
- authorship, ethics, CRediT, funding, conflict, data/code, and GenAI statements;
- artifact verification and submission readiness.

## Reopening rule

Reopen S2 if calibration-1 and the triggered calibration-2 both fail and show
that a unified action vocabulary is unstable across the four fields; then revise
RQ2/RQ3 to field-specific maintenance decisions and contract contribution 3.
Also reopen if the thesis, RQs, contribution ceiling, target venue, evidence
population, comparison set, or frozen protocol changes materially. Other
negative or mixed outcomes select Branch B without reopening S2.
