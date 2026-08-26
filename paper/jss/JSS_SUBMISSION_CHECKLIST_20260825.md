# JSS Submission Checklist

**Official source checked**: 2026-08-25
**Primary source**: Journal of Systems and Software, Guide for Authors,
https://www.sciencedirect.com/journal/journal-of-systems-and-software/publish/guide-for-authors

**Supporting official sources checked**: 2026-08-26

- Elsevier LaTeX instructions:
  https://www.elsevier.com/researcher/author/policies-and-guidelines/latex-instructions
- Elsevier research-data guidelines and data statement:
  https://www.elsevier.com/en-in/researcher/author/tools-and-resources/research-data/data-guidelines
  and
  https://www.elsevier.com/en-in/researcher/author/tools-and-resources/research-data/data-statement
- JSS official journal/Open Science page:
  https://shop.elsevier.com/journals/journal-of-systems-and-software/0164-1212
- CTAN `elsarticle` record:
  https://ctan.org/texarchive/macros/latex/contrib/elsarticle

**Current decision**: `NO_GO_FOR_SUBMISSION`. This checklist records current
official requirements and project status; it does not establish compliance or
submission readiness.

## 1. Venue and article form

| Requirement | Official requirement checked | Current project status | Gate |
|---|---|---|---|
| Scope and evidence | JSS covers software-engineering methods, maintenance/evolution, human/social aspects, and requires evidence for claims. | Candidate fit is maintenance-oriented empirical software engineering; deterministic RQ1/RQ2 evidence exists, while RQ3 analyst validation is missing. | **Blocked by E08/E09 for the complete paper**. |
| Length | Full papers are encouraged below 36 single-column or 18 double-column pages; longer manuscripts need justification. | No JSS-formatted PDF exists. | Check at S6. |
| Editable source | Entire submission must use editable source; PDF alone is not acceptable. Word should be single-column; double-column is allowed for LaTeX. | A flat editable `elsarticle` zero-draft source exists alongside Markdown; RQ3 and author-owned content remain missing. | Source mechanics are prepared; final result-bearing and author-approved source remains blocked. |
| LaTeX template | The guide encourages Elsevier's LaTeX template and requires all relevant editable sources. Elsevier's instructions identify `elsarticle` and warn that Editorial Manager does not process subfolders reliably. | Flat source instantiated with installed Elsevier-maintained `elsarticle` 3.5; template provenance recorded. | Mechanical template blocker cleared for the zero draft, not for the final paper. |
| Section numbering | Clearly numbered sections/subsections; abstract excluded from numbering. | Zero draft follows numbered-section planning but is not templated. | Pending conversion. |

No separate JSS-specific `.tex` class was identified on the guide page; the
official route points to Elsevier's `elsarticle` instructions. The official
downloadable example bundle was inspected in `/tmp` and not vendored. The
installed maintained class is version 3.5. This establishes a source route, not
the journal's author-anonymization mode.

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
| Reproducibility snapshot | Bind manuscript tables to exact data/code/results and provide a runnable path. | No-human allowlist manifest, source hashes, table generator, checked CSV/LaTeX tables, and validator exist. Human/private stages are explicitly excluded. |
| Open Science review | Optional additional availability/usability review described by JSS; it does not affect acceptance. | Not requested or performed. |

## 5. Tables, figures, references, and supplementary material

| Item | Official requirement | Current status |
|---|---|---|
| Tables | Editable text, consecutively numbered/cited, captions and notes, no unnecessary duplication. | Three editable deterministic tables are generated from one label-free source and render within the text block. Human-result tables remain intentionally absent. |
| Figures | Separately supplied, cited, numbered, logically named, with captions. | Planned only; no final result figure exists. |
| References | Consistent at submission; all in-text citations and reference-list entries must correspond; DOI use encouraged. | The zero draft has citation/BibTeX closure for 17 cited sources and a claim-level evidence map. One item remains explicitly abstract/metadata-only. Result-dependent and final artifact citations require later recheck. |
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

## 7. Result-independent build checkpoint

The editable zero draft compiles with `elsarticle` 3.5 and
`elsarticle-harv`. The checked temporary PDF has 22 pages and SHA-256
`0b88cda988422b2fc3b2fba1a9840ea7335f2deffcf4371db37847594908d269`.
The final log has no matched undefined-citation/reference warnings, other
LaTeX/package warnings, or overfull boxes. All 22 pages were rendered and
visually inspected; table, declaration, and reference pages received an
additional full-resolution check.

This checkpoint does not tick the final-PDF item above. The PDF contains result
and author placeholders, uses preparation metadata, and is neither
author-approved nor submission-ready.
