# JSS Citation and Evidence Map

**Checked:** 2026-08-26
**Scope:** citations used in the result-neutral JSS zero draft
**Decision boundary:** bibliographic metadata and source contents support
positioning only. They do not validate this paper's deterministic rules,
routing strategies, or future human results.

The local literature archive contains 24 targeted works: 23 verified full PDFs
and one abstract/metadata-only item. `references.bib` contains only works cited
in the zero draft, rather than mirroring the whole archive. DOI metadata was
checked through the DOI registry/publisher records; non-DOI entries use the
official USENIX, PMLR, NVD, GitHub, or arXiv page.

| BibTeX key | Primary or authoritative source | Local evidence | What the citation supports | What it does not support |
|---|---|---|---|---|
| `NVDDevelopers2026` | NIST NVD developer documentation | Live page checked; corpus remains repository-bound | NVD exposes structured vulnerability records and API fields | Correctness/completeness of any field or the frozen snapshot |
| `GitHubAdvisoryDatabase2026` | GitHub documentation | Live page checked; reviewed records are frozen locally | GHSA is a structured advisory source with reviewed records | GHSA superiority, universal review timing, or source truth |
| `Dong2019VIEM` | USENIX paper page and open PDF | Verified full PDF | Version extraction from public reports and comparison with NVD | Structured NVD--GHSA action routing |
| `Croft2022Severity` | IEEE DOI `10.1109/SANER53432.2022.00050` | Verified full PDF | Severity-label inconsistency across lifecycle sources; source choice can affect downstream models | Four-field action labels or a same-task baseline |
| `Sun2023Aspect` | ACM DOI `10.1145/3624734` | Verified full PDF | Aspect-level discrepancy taxonomy and detection across heterogeneous reports | First-discrepancy claims, action routing, or a correctness oracle |
| `Li2025VuldiffFinder` | Elsevier DOI `10.1016/j.cose.2025.104447` | Verified full PDF | Semantic inconsistency detection in unstructured vulnerability information | Structured field routing or human action truth |
| `Anwar2022CleaningNVD` | IEEE DOI `10.1109/TDSC.2021.3125270` | Verified full PDF | NVD quality assessment and correction candidates | Cross-source maintenance-action validity |
| `Johnson2018CVSS` | IEEE DOI `10.1109/TDSC.2016.2644614` | **Abstract/metadata only; closed full text** | Bayesian treatment of CVSS source quality at the abstract-level ceiling | Detailed methods, exact results beyond abstract, or routing claims |
| `Okutan2023Curation` | IEEE DOI `10.1109/TSE.2023.3250479` | Verified full PDF | Automated curation/characterization and empirical evaluation | Same-task cross-source routing |
| `Chen2025AffectedVersions` | IEEE DOI `10.1109/ASE63991.2025.00244` | Verified full PDF | Common-contract evaluation of 12 affected-version tools over 1,128 C/C++ vulnerabilities | A reproduced baseline on this corpus or all-language generalization |
| `Mozannar2020Defer` | Official PMLR page | Verified full PDF | Formal learning-to-defer task family and system-loss framing | A reproduced learned defer baseline here; this study does not train a rejector |
| `Segal2026GHSA` | ACM DOI `10.1145/3793302.3793360` | Verified full PDF and public artifact status | GHSA review-pipeline timing and process context | Field correctness or temporal generalization of this snapshot |
| `Ruan2024VulZoo` | arXiv `2406.16347` | Verified full PDF | Multi-source vulnerability-intelligence aggregation | Conflict resolution or independent truth |
| `Dunlap2024VFCFinder` | ACM DOI `10.1145/3634737.3657007` | Verified full PDF | Linking advisories to candidate patches | Correct affected versions or action labels |
| `Bhandari2021CVEfixes` | ACM DOI `10.1145/3475960.3475985` | Verified full PDF | CVE--fix--code lineage dataset and collection pipeline | An unconditional source oracle |
| `Croft2023DataQuality` | IEEE DOI `10.1109/ICSE48619.2023.00022` | Verified full PDF | Data-quality problems and auditing for vulnerability datasets | Correctness of the present status rules |
| `Li2023Anatomy` | Elsevier DOI `10.1016/j.jss.2023.111679` | Verified full PDF | Systematic mapping of vulnerability-database research and venue context | Empirical validation of the present method |

## Closest-work conclusion

The closest empirical overlap remains Sun et al.'s aspect-level discrepancy
study, VuldiffFinder, Croft et al.'s severity work, and the affected-version
tool benchmark. They establish discrepancy detection, field-specific
measurement, and same-field benchmarking. The present differential is narrower:
three frozen strategies route already observed structured NVD--GHSA field
differences to maintenance actions, count abstention inside total manual
routing, and reserve any strategy-validity claim for independent trained
analysts. This is a positioning claim, not a first-work claim.

No additional experiment is proposed from this citation pass. The closest works
do not release the same NVD--GHSA four-field action labels, so none can be
reproduced as a same-task human-action baseline without changing the frozen
contract.
