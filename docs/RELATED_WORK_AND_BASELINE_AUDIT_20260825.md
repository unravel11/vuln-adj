# JSS Closest-Work, Dataset, and Baseline Audit

**Checked on**: 2026-08-25
**Timing**: post-protocol publication-status and positioning refresh
**Scope**: CVE-aligned NVD--GHSA structured fields and action-oriented routing.

This refresh reuses the 24-paper evidence archive (23 verified local PDFs and
one abstract/metadata-only item) and checks current primary publication pages
for the closest work. It is not a systematic review and does not authorize a
new experiment. Publication-status corrections do not change the frozen V3.1
sample, strategies, thresholds, packets, evaluator, or tags.

## 1. Closest-work matrix

| Work | Existing ability | Missing ability relative to this study | Overlap risk | Evidence level |
|---|---|---|---|---|
| Aspect-level Information Discrepancies, TOSEM 2023, DOI 10.1145/3624734 | Aligns CVEs, extracts seven vulnerability aspects from heterogeneous reports, and evaluates aspect-level discrepancy detection. | Does not directly compare the four frozen structured NVD--GHSA fields or validate maintenance actions, abstention, and a strong field-aware routing comparator. | **Very high** for any `first taxonomy` or generic discrepancy-detection claim. | Verified local full PDF and publisher DOI metadata. |
| VuldiffFinder, Computers & Security 2025, DOI 10.1016/j.cose.2025.104447 | Detects semantic inconsistencies in unstructured vulnerability information through decomposition, representation, and inconsistency determination. | Detection is not factual source adjudication or action routing; no same-input NVD--GHSA four-field comparison is available. | **Very high** if this work is framed as merely detecting differences. | Verified local full PDF and current ScienceDirect article page. |
| Croft et al., SANER 2022 | Measures severity inconsistency across a Firefox reporting lifecycle and tests downstream label-source effects. | No per-case factual gold, no multi-field routing, and no abstention-aware action comparison. | High for a generic `differences affect downstream use` claim. | Verified local full PDF; author data/code recorded in the archive. |
| Automated Vulnerability Curation, TSE 2023 | Predicts 28 VDO attributes and evaluates prediction quality, timeliness, and estimated curation effort. | Generates attributes from text rather than routing disagreements between two structured sources; estimated effort is not observed action utility here. | Medium-high for an `AI assists curation` contribution. | Verified local full PDF and DOI metadata. |
| Vulnerability-Affected Versions Identification, **ASE 2025**, DOI 10.1109/ASE63991.2025.00244 | Provides a 1,128-vulnerability C/C++ benchmark and evaluates 12 affected-version tools on a common contract. | Its task is code/release-based affected-version identification, not classifying NVD--GHSA field differences or routing maintenance actions. | High for affected-version method or benchmark claims; medium for the overall routing paper. | Verified local author/arXiv PDF; formal ASE 2025 Research Paper status confirmed on the official conference page. |
| Learning to Defer, ICML 2020 | Formalizes classifier/expert system loss and learns instance-level deferral using expert decisions. | Requires representative expert decisions and a learned rejector; this study has deterministic strategies and, at present, no returned human actions. | High for theory/framing; low as a directly runnable same-task algorithm. | Official PMLR paper page, PDF, supplement, and software link; verified local PDF. |
| GHSA Review Pipeline, **MSR 2026**, DOI 10.1145/3793302.3793360 | Characterizes reviewed/unreviewed advisories, review latency, and fast/slow paths; releases data and analysis code. | Review status and timing do not establish field correctness, factual authority, or future-snapshot validity for this study. | Medium for publication-date mechanism claims; low for action routing. | Official MSR 2026 paper page, arXiv full text, and public reproduction repository. |
| Bayesian CVSS Analysis, TDSC 2018 | Abstract describes latent-truth/source-quality inference across CVSS sources without direct gold. | Full modeling assumptions, data, baselines, sensitivity, and reproducibility remain unverified locally; not an action-routing study. | High for severity/source-preference claims. | **Abstract/metadata only, closed access**; no local full PDF. |

The closest intersection is not a single paper. TOSEM/VuldiffFinder occupy
discrepancy detection, Croft/Automated Curation connect metadata to downstream
use, and Learning to Defer formalizes expert routing. The defensible candidate
differential is therefore the combination of structured field inputs, a strong
field-aware comparator, action-first/reason-second independent analyst
judgments, explicit abstention, reviewer-specific paired comparison, and a
precommitted boundary/no-go route. This differential remains conditional until
E08/E09 exist.

## 2. Public datasets and reusable resources

| Resource | Public/reproducible asset | Same-task fit | Current project use |
|---|---|---|---|
| ASE 2025 affected-version benchmark | Paper states that replicated code and the 1,128-vulnerability benchmark are released. | Same field, different task/population (C/C++ code/release truth). | Cited and inventoried; **not run as a baseline in this project**. |
| GHSA review-pipeline repository | Data files, collection scripts, and notebooks for the MSR 2026 analyses. | Same source ecosystem; review process rather than field routing. | Contextual resource only; **not imported into the frozen corpus**. |
| Croft severity package | Author data/scripts recorded by the archive. | Same field but one-project lifecycle and different outcome. | Related-work evidence; **not reproduced on a common contract**. |
| VulZoo | Multi-source vulnerability-intelligence dataset. | Useful external resource, not a gold source for aligned NVD--GHSA actions. | Cited/inventoried only. |
| VFCFinder and CVEfixes | Public code/data linking vulnerabilities to fixes. | Potential evidence for references/affected versions, not an unconditional source truth. | Cited/inventoried; no new integration authorized. |
| ICSE data-quality reproduction package | Reproducible software-vulnerability-dataset quality study. | Different object (code datasets rather than advisory fields). | Conceptual comparator only. |

No public dataset identified in the archive provides the same input contract,
the same four maintenance actions, two independent action-first/reason-second
trained-analyst passes, and the same three frozen routing strategies. That is a
task-contract gap, not evidence that the proposed construct is valid.

## 3. Same-task and closest baselines

| Baseline / arm | Reproducibility status | Role | Claim boundary |
|---|---|---|---|
| `binary_observed_non_equal` | Implemented and frozen over all 32,264 instances. | Raw-difference lower reference. | Not the main comparator and not a correctness oracle. |
| `binary_canonical_non_equal` | Implemented and frozen. | Separates normalization effects from type/action effects. | Not evidence that canonical equality is factual equality. |
| `field_aware_simple_v1` | Implemented, frozen, and selected before human exposure. | **Main strong comparator**. | Hand-written strategy, not observed practitioner behavior. |
| `type_first_current_v1` | Implemented and frozen. | Efficiency candidate. | No efficiency or superiority claim before E08/E09. |
| `type_first_abstention_v1` | Implemented and frozen. | Safety/coverage candidate. | Abstention is a manual route, not zero cost or proven safety. |
| `always_manual` | Implemented and frozen. | Manual-route upper reference. | Does not represent measured labor. |
| `abstain_all` | Implemented and frozen. | No-automation boundary reference. | Not a deployable recommendation. |
| Published affected-version tools | Paper/benchmark assets identified. | Closest same-field external baseline if automated truth adjudication becomes a core claim. | **Not reproduced here**; do not claim comparison or improvement. |
| Learning-to-defer algorithms | Official paper/software identified. | Theoretical closest routing family. | Not same-task without training labels, loss contract, and expert behavior data. |

The current baseline package is sufficient for the frozen routing question
because it contains raw/canonical lower references, a strong field-aware main
comparator, two type-first candidates, and two boundary arms. It is not
sufficient for a new claim that the project automatically identifies true
affected versions or learns an optimal human deferral policy. Such claims are
outside the current route and would require separately authorized protocols.

## 4. Literature-driven decisions

- Keep the trained-analyst, not practitioner, framing.
- Keep raw/canonical non-equality as lower references and
  `field_aware_simple_v1` as the main comparator.
- Do not add a learned deferral model: no frozen same-task training labels or
  authorized learned-policy experiment exists.
- Do not reopen affected-version adjudication: the external benchmark raises
  the baseline burden, while the current project result is a bounded no-go.
- Update publication metadata for entries 05 and 13; retain entry 18 as
  abstract/metadata-only.
- Re-run a narrow publication-status refresh before actual submission because
  2025--2026 records can still change.

## 5. Sources checked in this refresh

- JSS official Guide for Authors:
  https://www.sciencedirect.com/journal/journal-of-systems-and-software/publish/guide-for-authors
- ASE 2025 official paper page:
  https://conf.researchr.org/details/ase-2025/ase-2025-papers/106/Vulnerability-Affected-Versions-Identification-How-Far-Are-We-
- MSR 2026 official paper page:
  https://2026.msrconf.org/details/msr-2026-technical-papers/27/Characterizing-and-Modeling-the-GitHub-Security-Advisories-Review-Pipeline
- MSR 2026 reproduction repository: https://github.com/cmsegal/ghsa-review
- PMLR official paper page:
  https://proceedings.mlr.press/v119/mozannar20b.html
- VuldiffFinder ScienceDirect page:
  https://www.sciencedirect.com/science/article/pii/S0167404825001361

Mechanical file/PDF checks prove archive identity and availability only. They
do not prove the papers' conclusions, this paper's novelty, or submission
readiness.
