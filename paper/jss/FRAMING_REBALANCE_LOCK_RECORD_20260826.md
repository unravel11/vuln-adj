# JSS Routing-Centric S2 Rebalance Lock Record

## Decision

- Date: 2026-08-26 (Asia/Singapore)
- Trigger: the author questioned whether the paper made human annotation too
  central and authorized a fresh Claude Opus Max review and corresponding S2
  correction.
- Decision: `AUTHOR_LOCKED_ROUTING_CENTRIC_S2`
- Resulting stage: `S2_ARGUMENT_LOCKED`
- Scientific effect: none. This record changes the argument hierarchy; it does
  not create human labels, E08/E09, policy correctness, safety, utility,
  superiority, or submission readiness.

## Authority and pre-rebalance snapshot

- Host: `code-defender`
- Workspace: `/home/xiaoyuliang/code/vuln-adj`
- Branch: `codex/jss-zero-draft-venue-20260825`
- Pre-rebalance HEAD: `c2adecf5090ddc64ef9597140cb2d0423af279af`
- Pre-rebalance Git state: clean; upstream divergence `0/0`
- Human evidence: zero real-human returns; E08/E09 remain
  `MISSING_OR_UNRESOLVED`
- Frozen protocols, samples, thresholds, policies, tags, and packets: unchanged

## Claude Max challenge record

- Claude Code: `2.1.226`
- Model: `claude-opus-5`
- Effort: `max`
- Session ID: `91195c45-1a4c-45f7-a0ea-54871ffb0b98`
- Permissions: read-only; only `Read`, `Grep`, and `Glob` allowed; edit, write,
  Bash, and web tools denied
- Exclusions: `.env`, private reviewer material, reason, calibration-2, formal
  packets, experiments, repository edits, and web browsing
- Raw session record:
  `/home/xiaoyuliang/.claude/projects/-home-xiaoyuliang-code-vuln-adj/91195c45-1a4c-45f7-a0ea-54871ffb0b98.jsonl`
- Raw-record SHA-256 after the decisive turn:
  `c6fdc745f5dd44e7453ccf59a70f6f7684a50ff6b2d1ad826148a95d74314266`

The first Max turn returned `REBALANCE_AND_RELOCK`, but its proposed wording
still retained `Human` in the title, called label-free queue counts a safety
frontier, left two RQs human-dependent, and treated negative-result governance
as a standalone scientific contribution. Codex challenged those upgrades. In
the same Max session, Claude returned `ACCEPT_CORRECTIONS` and endorsed a
two-deterministic-RQ plus one-human-validation-RQ architecture. The exact lock
below also corrects the model's phrase `strategy-disagreement cases`, because
the frozen formal set contains a predeclared shared-no-manual audit as well as
policy-disagreement cases.

This exchange is an advisory governance stress test, not independent human
review and not scientific evidence.

## Author-locked title

_When Vulnerability Metadata Differ: Routing Trade-Offs across Field-Level
NVD–GHSA Strategies_

## Author-locked one-sentence thesis

For CVE-aligned NVD–GHSA record pairs across four fields, three frozen routing
strategies produce different conflict-escalation, abstention, and total
manual-route allocations; independent trained-analyst judgments test whether
those deterministic differences correspond to differentiated maintenance
actions or expose an empirical decision boundary.

## Author-locked research questions

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

RQ1 and RQ2 are answerable from E01/E07B. RQ3 and every human-backed result
remain blocked on valid E08/E09. Analyst agreement and reason coding are RQ3
validity diagnostics, not a standalone research object.

## Exactly three author-locked contributions

1. **Reproducible four-field deterministic census.** A snapshot- and
   pipeline-bounded census of 8,066 CVE-aligned NVD–GHSA pairs and 32,264 field
   instances, with deterministic statuses for severity, affected versions,
   publication date, and references. It cannot support database quality,
   ground truth, broader prevalence, causal explanation, or correctness.
2. **Decision-oriented three-strategy routing comparison.** A frozen comparison
   with explicit conflict-escalation, abstention, and total-manual-route
   accounting. On the frozen corpus, the abstention-aware candidate has 74 fewer
   conflict escalations but 950 more total manual routes than the strong
   field-aware comparator. This is a deterministic queue-allocation trade-off,
   not correctness, workload, safety, utility, or superiority.
3. **Sample- and analyst-bounded validation or decision boundary.** Two
   independent trained analysts are evaluated under the frozen calibration,
   action-stage lock, recursive blinding, formal-sample, and stop-rule contract.
   Valid returns can support either reviewer-consistent strategy
   differentiation or an observed reliability, agreement, coverage,
   abstention, shared-miss, or identifiability boundary. Before E08/E09, neither
   outcome is claimed. If calibration terminates formal distribution, that
   failure is retained as the observed construct boundary.

Action-first/reason-second ordering, blinding, and stop rules remain essential
Method details supporting contribution 3. They are no longer presented as a
standalone protocol contribution. Retrospective reconciliation-limit evidence
remains supporting discussion material, not a fourth contribution.

## Result branches

- **Branch P:** only if both reviewers clear every frozen reliability,
  paired-direction, event-floor, coverage, and manual-loss gate. RQ3 may then
  report reviewer-consistent strategy differentiation for this sample and
  these trained analysts. It still cannot claim practitioner behavior,
  operational safety, saved labor, or universal superiority.
- **Branch B:** mandatory if calibration terminates, reviewer directions differ,
  reliability or event floors fail, manual-route coverage fails, or shared
  misses appear. RQ3 then reports the observed decision or identifiability
  boundary without changing fields, cases, policies, thresholds, or labels.

RQ1, RQ2, C1, and C2 remain the same under both branches. Human outcomes select
the RQ3/C3 disposition; they do not change the deterministic findings.

## S2 reopening and relock

The author-triggered change to title, thesis, RQs, and contribution ceiling
materially reopened S2. The synchronized argument plan, question/evidence map,
section and figure/table plan, related-work differential, explicit non-claims,
minimum sufficient story, and dual-branch stop rule complete the replacement
lock. The resulting stage is again `S2_ARGUMENT_LOCKED`.

Reopen S2 later only if the thesis, RQs, contribution ceiling, venue, evidence
population, comparison set, or frozen protocol changes materially, or if both
calibration rounds show that the unified action vocabulary is unstable across
the four fields. Arrival of human results and selection of Branch P or B do not
by themselves reopen S2.

## Explicitly unlocked

- E08/E09 and every RQ3 empirical statistic;
- Branch P/B selection and result-dependent headings;
- abstract, conclusion, highlights, and final references;
- zero-draft prose approval and reconciliation-limit placement;
- authorship, ethics, CRediT, funding, conflict, data/code, and GenAI statements;
- artifact verification and submission readiness.
