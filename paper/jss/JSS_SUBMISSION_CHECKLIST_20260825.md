# JSS Submission Checklist

**Official source checked**: 2026-08-25
**Primary source**: Journal of Systems and Software, Guide for Authors,
https://www.sciencedirect.com/journal/journal-of-systems-and-software/publish/guide-for-authors

**Current decision**: `NO_GO_FOR_SUBMISSION`. This checklist records current
official requirements and project status; it does not establish compliance or
submission readiness.

## 1. Venue and article form

| Requirement | Official requirement checked | Current project status | Gate |
|---|---|---|---|
| Scope and evidence | JSS covers software-engineering methods, maintenance/evolution, human/social aspects, and requires evidence for claims. | Candidate fit is maintenance-oriented empirical software engineering; deterministic RQ1/RQ2 evidence exists, while RQ3 analyst validation is missing. | **Blocked by E08/E09 for the complete paper**. |
| Length | Full papers are encouraged below 36 single-column or 18 double-column pages; longer manuscripts need justification. | No JSS-formatted PDF exists. | Check at S6. |
| Editable source | Entire submission must use editable source; PDF alone is not acceptable. Word should be single-column; double-column is allowed for LaTeX. | S2 argument is author locked, but the current zero draft is Markdown and RQ3 remains missing. | Convert after branch selection and author revision; S2 lock alone does not justify a final submission source. |
| LaTeX template | The guide encourages Elsevier's LaTeX template and requires all relevant editable sources. | No current JSS/Elsevier template has been instantiated. | Open format blocker, not a scientific blocker. |
| Section numbering | Clearly numbered sections/subsections; abstract excluded from numbering. | Zero draft follows numbered-section planning but is not templated. | Pending conversion. |

No separate JSS-specific `.tex` template was identified on the guide page; the
official route points to Elsevier's LaTeX instructions/templates. Do not claim a
template package has been downloaded or validated until that action occurs.

## 2. Front matter and separate files

| Item | Official requirement | Current status |
|---|---|---|
| Title | Concise and informative; avoid uncommon abbreviations/formulae. | Routing-centric title is author locked at S2; final front-matter approval remains author owned. |
| Authors and affiliations | Names/order must match the submission system; full affiliations and corresponding-author details are required. | Author-owned and unresolved. |
| Abstract | Concise, factual, standalone, at most 250 words; normally no references. | Intentionally withheld until the RQ3 result branch exists. |
| Keywords | 1--7 English keywords. | Title is author locked; keywords remain candidate and must match the result-dependent abstract. |
| Highlights | Separate editable file; 3--5 bullets; each at most 85 characters including spaces. | Intentionally withheld because novel results are not yet known. |
| Graphical abstract | Encouraged, not recorded as mandatory. | Not planned before result branch selection. |
| Author biographies | Editable biography, maximum 100 words per author. | Author-owned and unresolved. |

## 3. Ethics, authorship, and declarations

| Item | Official requirement | Current status |
|---|---|---|
| Submission declaration | Work not simultaneously under consideration; publication approved by all authors/responsible authorities. | Must be confirmed by authors at submission. |
| Authorship | Substantial contribution, critical drafting/revision, final approval, and accountability; changes after submission are restricted. | Order and author approval unresolved. |
| Competing interests | A declaration is required through the journal workflow, including a no-interest declaration where applicable. | Unresolved. |
| Funding | Funding source and sponsor role must be stated; a no-specific-grant sentence is recommended when applicable. | Unresolved. |
| CRediT | Corresponding author must report applicable CRediT roles. | Unresolved. |
| Human participation/ethics | Report the real applicable institutional determination and consent/recruitment conditions accurately. | R2 is author-attested and not independently verified by Codex; manuscript wording remains author/institution owned. |
| Generative AI | If AI tools were used in manuscript preparation beyond basic grammar/spelling/reference checking, add the journal's required declaration before the references; AI cannot be an author. | A declaration will be required because Codex assisted the zero draft. Authors must specify tool, purpose, review, and responsibility. |

## 4. Data, code, and open-science material

The guide applies Elsevier research-data **Option C** to JSS. Authors are
required to deposit research data in a relevant repository and cite/link it, or
state why sharing is not possible. A data-availability statement is required at
submission. JSS also describes an Open Science material review route; successful
availability/usability review is separate from paper acceptance.

| Item | Required preparation | Current status |
|---|---|---|
| Data statement | State data availability at submission. | Placeholder only; no author-approved statement. |
| Dataset deposit/citation | Deposit and cite/link the research data, or give a reason it cannot be shared. | Repository contains local payload and hashes, but no public archival PID/URL is frozen. |
| Code/software citation | Cite software/code with creator, title, venue/repository, date/version, identifier, and type where applicable. | Git history exists; no archival release/PID is frozen. |
| Protocol/codebook | Share or explain restrictions for V3.1 protocols, codebooks, and anonymized returns. | Protocol/tooling exists; real returns do not. Reviewer-private material must remain private. |
| Reproducibility snapshot | Bind manuscript tables to exact data/code/results and provide a runnable path. | Source hashes and validators exist; JSS artifact snapshot not built. |
| Open Science review | Optional additional availability/usability review described by JSS; it does not affect acceptance. | Not requested or performed. |

## 5. Tables, figures, references, and supplementary material

| Item | Official requirement | Current status |
|---|---|---|
| Tables | Editable text, consecutively numbered/cited, captions and notes, no unnecessary duplication. | Planned only; human-result tables intentionally absent. |
| Figures | Separately supplied, cited, numbered, logically named, with captions. | Planned only; no final result figure exists. |
| References | Consistent at submission; all in-text citations and reference-list entries must correspond; DOI use encouraged. | Zero draft uses explicit citation placeholders and is not reference-complete. |
| Dataset/software references | Cite datasets/software as first-class references, not only the describing paper. | Pending public artifact decision. |
| Supplementary files | Upload and describe any supplementary materials. | Scope unresolved; do not expose private reviewer materials. |
| Copyright permission | Obtain permission for third-party copyrighted material. | No third-party figure reuse is currently planned. |

## 6. Final submission checklist and project disposition

- [ ] Both independent V3.1 returns and all frozen E08/E09 gates completed.
- [ ] Positive or boundary result branch selected without post-result protocol
  change.
- [ ] Title, abstract (<=250 words), 1--7 keywords, and 3--5 highlights (<=85
  characters each) author approved.
- [ ] Editable Elsevier/JSS source instantiated and full manuscript kept within
  the encouraged length or accompanied by a justification.
- [ ] All tables/figures tied to authoritative data and supplied in editable or
  required separate formats.
- [ ] Authors/order, affiliations, corresponding-author contact, biographies,
  funding, conflicts, CRediT, acknowledgements, and institutional ethics wording
  resolved.
- [ ] Generative-AI declaration drafted and author approved.
- [ ] Data statement, public archive/PID or justified restriction, software and
  dataset citations, license, and artifact manifest resolved.
- [ ] Citation/reference consistency, language, spelling, permissions,
  anonymity/peer-review handling, and submission-system fields rechecked against
  the live guide immediately before submission.
- [ ] Final PDF built and every page visually inspected after the final source
  change.
- [ ] External upload/submission separately authorized by the corresponding
  author.

The live guide scrape used for this checklist did not yield a reliable explicit
statement of JSS's current author-anonymization mode. Treat anonymity handling
as `UNRESOLVED_RECHECK_LIVE`, not as single- or double-anonymized by inference.
