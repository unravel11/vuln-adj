# COSE Method Innovation Review

Date: 2026-05-28

Scope: reviewer-style assessment of whether the current method chapter, method framework diagram, and HTML explainer can support a Computers & Security paper innovation claim.

## Verdict

Current acceptance risk is high if the paper is submitted as a finished empirical method paper. The method is a defensible problem-formulation and workflow contribution, but it is not yet a validated security-data method because RQ2 has blank human labels and RQ3 remains silver-label/prototype only.

The strongest safe positioning is:

> Post-CVE-alignment structured-field discrepancy typing for NVD-GHSA pairs, followed by evidence-constrained source-support adjudication with abstention for sampled factual conflicts.

The concise reviewer-facing phrase is:

> triage before truth

That is, the paper first determines what kind of field-level difference exists, then adjudicates only residual factual conflicts.

## Defensible Innovation Boundary

The current method can credibly claim:

- a post-alignment structured-field discrepancy task for paired NVD-GHSA records;
- a field-aware taxonomy separating equivalent values, representation differences, incompleteness, temporal discrepancies, and residual factual conflicts;
- deterministic, auditable field-view construction and baseline typing over 8,066 CVE-aligned pairs;
- an evidence-context construction step that separates reference provenance from source correctness;
- an abstention-capable source-support decision space: NVD, GHSA, both, neither, abstain;
- an audit-ready workflow that keeps silver labels separate from human-gold claims.

This is a task/taxonomy/workflow contribution, not a new generic truth-discovery algorithm.

## Claims To Avoid

Do not claim:

- solved vulnerability database fusion;
- final NVD-GHSA source-of-truth adjudication;
- RQ2 accuracy, precision, recall, macro-F1, or agreement before human labels exist;
- RQ3 human-gold adjudication performance before audit rows are final;
- semantic affected-version range adjudication;
- validated affected_versions false-positive rates;
- silver-v2 labels as gold labels;
- a complete closed-loop system before RQ2/RQ3 gold validation is done.

## Acceptable Claim Wording

Acceptable:

> We introduce the post-alignment field-level discrepancy typing task for structured NVD-GHSA vulnerability records and instantiate it with a deterministic, field-aware baseline over 8,066 CVE-aligned pairs.

Acceptable:

> The deterministic baseline assigns many binary field differences to non-conflict categories, motivating a type-first workflow before evidence-based adjudication.

Acceptable:

> We prototype evidence-constrained adjudication for sampled severity and affected_versions conflicts using fetched advisory evidence and an abstention-capable source-support decision space.

Acceptable:

> The current evidence-aware adjudication results are silver-label diagnostics and should not be interpreted as human-gold source-truth performance.

## Main Weaknesses

- RQ2 is currently a rule-trigger diagnostic, not an evaluation.
- RQ3 is silver-only and partly LLM-derived.
- affected_versions is the weakest field because the current prototype uses token support rather than package-aware and range-aware semantics.
- Evidence availability is fetch-biased, especially for GitHub advisory / repository / commit pages.
- The package validator can pass integrity while still reporting `submission_ready=false`.

## Required Before COSE Submission

- Complete RQ2 300-instance primary labels.
- Complete the RQ2 20% consistency review and report agreement.
- Complete RQ3 human audit for severity and affected_versions.
- Run the guarded RQ3 evaluator and report human-gold metrics.
- Compare against fixed-source, latest-published, normalized-only, and simple heuristic baselines using human labels.
- Add selective adjudication reporting: coverage versus gold-backed correctness.
- Either implement package-aware / range-aware affected_versions adjudication or keep affected_versions explicitly diagnostic-only.
- Replace silver-label case sketches with human-verified cases or keep them clearly marked as sketches.

## Method Chapter Implications

The method chapter should:

- use "implemented baseline pipeline" for unvalidated behavior;
- foreground the type-first workflow as the method's core;
- present the 1,272-to-652 affected_versions reduction as an implementation diagnostic, not an improvement claim;
- describe silver-v2 as an annotation aid and diagnostic target, not an oracle;
- add validation-status language after each method stage;
- avoid "supports" unless tied to human audit; prefer "matches fetched-evidence cues" or "provisionally labeled as supported";
- keep the final boundary explicit: current method assets are a pre-submission scaffold until gold-backed validation exists.

## Independent Multi-Agent Reviewer Check

Date: 2026-05-28

Setup: three read-only reviewer agents independently assessed the current method from novelty/COSE positioning, method rigor/validation, and related-work differentiation perspectives.

Consensus verdict:

- As a task, taxonomy, and auditable workflow contribution, the method is defensible but moderate in strength.
- As a finished empirical method or automated adjudication system, the current version is not yet defensible for COSE submission.
- The likely editorial posture before gold-backed validation is borderline to weak reject / major revision, not accept.

Reviewer-specific findings:

- Novelty/positioning reviewer: judged the innovation as medium but conditional on presenting it as "task definition + field-level taxonomy + auditable baseline workflow" rather than a validated vulnerability-data fusion method.
- Method-rigor reviewer: judged the current evidence insufficient for a method-effectiveness claim because RQ2 has no human gold labels and RQ3 remains silver/prototype only.
- Related-work reviewer: judged the differentiation plausible against unstructured advisory mining and generic truth discovery, but vulnerable to an "incremental data-cleaning pipeline" criticism unless the type-first contribution is emphasized.

Unified claim boundary:

> Binary disagreement is not factual conflict; vulnerability-record fusion must first type the field-level discrepancy, then adjudicate only residual factual conflicts under explicit evidence and abstention.

Concrete COSE risk points:

- `affected_versions` remains the weakest field because current adjudication uses token support rather than package-aware and range-aware semantics.
- Silver-label agreement can support diagnostic discussion, but not accuracy, correctness, or source-truth claims.
- The current artifact can show reproducibility and audit readiness, but not validated source-of-truth performance.
- A submission that foregrounds LLM/silver-label adjudication would create both validity and venue-fit risk.

Recommended submission gate:

- Complete RQ2 primary labels and consistency review before claiming typing performance.
- Complete RQ3 human audit before claiming adjudication performance.
- Either implement package-aware/range-aware `affected_versions` adjudication or keep that field explicitly diagnostic-only.
- Add a related-work comparison table contrasting input type, alignment stage, discrepancy taxonomy, evidence use, adjudication target, abstention, and affected-version schema handling.

## Second Reviewer Pass: Method Completeness

Date: 2026-05-28

Setup: three additional read-only reviewer agents assessed the same material from novelty, methods rigor, and evaluation-support perspectives. This pass focused on whether the generated method can be treated as a paper innovation point and whether the method chapter is finished enough for COSE submission.

Consolidated verdict:

- The method can be used as a conditional innovation point if framed narrowly as post-CVE-alignment structured-field discrepancy typing, a field-aware routing contract, an auditable deterministic baseline, and an abstention-capable evidence handoff.
- The current method chapter is not yet methods-ready for a full COSE empirical-method submission. It is a scaffold/baseline draft with strong claim guards.
- The current experimental evidence supports problem motivation, reproducible diagnostics, evidence availability, and audit readiness. It does not yet support validated typing performance, source-truth adjudication performance, or semantic `affected_versions` adjudication.

Specific reviewer consensus:

- Novelty: conditional. The defensible novelty is "binary disagreement is not factual conflict" plus a type-first routing contract. If written as automated vulnerability-record fusion or truth resolution, the contribution will likely be judged as ordinary data cleaning or an unvalidated pipeline.
- Method rigor: incomplete. The chapter still needs formal input/output contracts, field-view schema, stage output definitions, adjudication label definitions, rule priority/tie-breaking, pseudocode, concrete examples, and explicit RQ1/RQ2/RQ3 mapping.
- Evaluation support: insufficient for a validated method claim. RQ1 supports scale and motivation; RQ2 currently has blank human labels; RQ3 remains silver-only with severity `0/80` and `affected_versions` `0/100` final human-audit rows.

Required method-chapter additions before submission:

- Add an explicit field-view schema: original source values, normalized comparison values, provenance, rule note, sample/field identifiers, and emitted discrepancy type.
- Add a rule-priority table or decision procedure for each field, including how `representation_discrepancy`, `incomplete`, and residual `factual_conflict` are separated.
- Add pseudocode for field-view construction/discrepancy typing and evidence-constrained adjudication with abstention.
- Define `NVD-supported`, `GHSA-supported`, `both`, `neither`, and `abstain` operationally, separating text-token silver support from human factual support.
- Add short method examples for severity, published/date, references, and `affected_versions`.
- Tie method stages directly to RQ1/RQ2/RQ3 and state which claims are available now versus pending human gold.
- Keep `affected_versions` diagnostic-only unless package identity, ecosystem version ordering, and range containment are implemented and human-validated.

Submission implication:

The current safest paper type is an exploratory diagnostic study or a baseline/task-definition paper. To submit as a stronger COSE method paper, the project needs RQ2 human discrepancy-typing validation and RQ3 human-audited adjudication validation. Until then, silver-label agreement, deterministic rule-trigger distributions, and case sketches should remain diagnostic evidence, not performance evidence.

## Third Reviewer Pass: Current Method After IO/Procedure Updates

Date: 2026-05-28

Setup: three read-only reviewer agents reassessed the current method after the method chapter was expanded and then compressed. The reviewers covered COSE novelty positioning, methodological rigor/evidence sufficiency, and related-work differentiation. This pass supersedes the earlier method-completeness concerns about missing IO contracts and procedure descriptions: the current method chapter now contains field-instance input, stage output contracts, ordered field-specific rule paths, procedure prose, evidence/adjudication boundaries, and RQ maturity mapping.

Current answer to "is the method chapter written?":

- As a paper method section draft, yes: the chapter now states the method's operational unit, stages, routing contract, rule paths, evidence context, adjudication labels, and validation boundaries.
- As a submission-ready validated method, no: the chapter still cannot support typing-performance or adjudication-performance claims because RQ2 and RQ3 human-gold validation remain incomplete.

Consolidated COSE reviewer verdict:

- The generated method can be a defensible innovation point only if framed as a scoped method framework: post-CVE-alignment structured-field discrepancy typing, field-aware taxonomy, auditable deterministic baseline, and evidence-constrained handoff for residual factual conflicts.
- The strongest concise contribution is: type the field-level discrepancy before asking which source is correct.
- The method is not yet defensible as an automatic vulnerability-record fusion system, source-of-truth resolver, generic truth-discovery algorithm, or semantic `affected_versions` adjudicator.
- Without RQ2/RQ3 human gold, the likely COSE posture remains borderline or major-revision risk rather than a strong accept.

Evidence supporting the innovation claim:

- The problem is not record alignment but post-alignment field disagreement: aligned NVD-GHSA records can differ by field even under the same CVE.
- The five-way discrepancy taxonomy gives operationally different downstream actions: normalize equivalent/representation cases, augment incomplete cases, interpret temporal cases, and adjudicate only residual factual conflicts.
- The evidence layer separates reference provenance from source truth and permits `NVD`, `GHSA`, `both`, `neither`, and `abstain` decisions rather than forcing winner-only fusion.
- The audit interface makes the current boundary explicit by preserving silver labels, fetched evidence, and blank human-audit fields.

Residual rejection risks:

- A reviewer may still see the work as field-difference statistics plus deterministic data-cleaning rules unless the type-first routing contract is foregrounded.
- `affected_versions` remains the weakest field because the current prototype is structural/token-support based, not package-aware or range-aware semantic adjudication.
- Silver-label diagnostics can motivate audit and compare patterns, but they cannot establish correctness, accuracy, or source-truth performance.
- Related-work comparison should keep separating this work from severity inconsistency studies, NVD quality audits, vulnerability text discrepancy mining, schema cleaning, and generic truth discovery.

Submission gate remains unchanged:

- Finish RQ2 primary labels and consistency review before reporting typing accuracy, agreement, precision, recall, or macro-F1.
- Finish RQ3 severity and `affected_versions` human audit before reporting adjudication performance.
- Keep `affected_versions` diagnostic-only unless package identity, ecosystem version ordering, and range containment are implemented and human-validated.
- Keep LLM/silver labels as annotation aids and diagnostics, not as gold labels or the core contribution.
