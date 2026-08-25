#!/usr/bin/env python3
"""Build and validate the related-work evidence manifest."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
PAPERS = ROOT / "docs" / "related_work_papers"
OUTPUT = PAPERS / "literature_manifest.json"

REQUIRED_HEADINGS = [
    "## 1. 论文一句话定位",
    "## 2. 论文要解决的问题",
    "## 3. 核心贡献拆解",
    "## 4. 方法揉碎讲解",
    "## 5. 实验逻辑",
    "## 6. 论文真正证明了什么",
    "## 7. 局限与风险",
    "## 8. 可复述版本",
    "## 9. 对本项目的可迁移点",
    "## 10. 审稿式评价",
]

METADATA = [
    ("01_viem_usenix_2019", "Towards the Detection of Inconsistencies in Public Security Vulnerability Reports", 2019, "USENIX Security", "https://www.usenix.org/conference/usenixsecurity19/presentation/dong", "full_pdf"),
    ("02_croft_saner_2022", "An Investigation into Inconsistency of Software Vulnerability Severity across Data Sources", 2022, "SANER", "https://arxiv.org/abs/2112.10356", "full_pdf"),
    ("03_flaw_within_cloudcom_2023", "The Flaw Within: Identifying CVSS Score Discrepancies in the NVD", 2023, "IEEE CloudCom", "https://people.scs.carleton.ca/~lianyingzhao/Inconsistency_NVD-authorscopy.pdf", "full_pdf"),
    ("04_cleaning_nvd_tdsc_2022", "Cleaning the NVD: Comprehensive Quality Assessment, Improvements, and Analyses", 2022, "IEEE TDSC", "https://arxiv.org/abs/2006.15074", "full_pdf"),
    ("05_affected_versions_arxiv_2025", "Vulnerability-Affected Versions Identification: How Far Are We?", 2025, "ASE 2025 Research Papers", "https://conf.researchr.org/details/ase-2025/ase-2025-papers/106/Vulnerability-Affected-Versions-Identification-How-Far-Are-We-", "full_pdf"),
    ("06_cvss_user_centric_sp_2024", "Shedding Light on CVSS Scoring Inconsistencies: A User-Centric Study", 2024, "IEEE S&P", "https://arxiv.org/abs/2308.15259", "full_pdf"),
    ("07_aspect_level_tosem_2023", "Aspect-level Information Discrepancies across Heterogeneous Vulnerability Reports", 2023, "ACM TOSEM", "https://doi.org/10.1145/3624734", "full_pdf"),
    ("08_aspects_threat_intel_acm_2025", "Vulnerability Aspects Extraction and Discrepancies Detection across Heterogeneous Threat Intelligence", 2025, "ACM/preprint", "https://doi.org/10.1145/3709018.3736330", "full_pdf"),
    ("09_vuldifffinder_cose_2025", "VuldiffFinder: Discovering Inconsistencies in Unstructured Vulnerability Information", 2025, "Computers & Security", "https://doi.org/10.1016/j.cose.2025.104447", "full_pdf"),
    ("10_gapfinder_tifs_2021", "GapFinder: Finding Inconsistency of Security Information From Unstructured Text", 2021, "IEEE TIFS", "https://ieeexplore.ieee.org/document/9121316", "full_pdf"),
    ("11_crh_sigmod_2014_tkde_2016", "Conflicts to Harmony: A Framework for Resolving Conflicts in Heterogeneous Data by Truth Discovery", 2016, "IEEE TKDE", "https://doi.org/10.1109/TKDE.2016.2559481", "full_pdf"),
    ("12_truth_discovery_survey_tbd_2024", "A Survey on Truth Discovery: Concepts, Methods, Applications, and Opportunities", 2024, "IEEE Transactions on Big Data", "https://doi.org/10.1109/TBDATA.2024.3423677", "full_pdf"),
    ("13_ghsa_review_pipeline_arxiv_2026", "Characterizing and Modeling the GitHub Security Advisories Review Pipeline", 2026, "MSR 2026 Technical Papers", "https://2026.msrconf.org/details/msr-2026-technical-papers/27/Characterizing-and-Modeling-the-GitHub-Security-Advisories-Review-Pipeline", "full_pdf"),
    ("14_vulzoo_arxiv_2024", "VulZoo: A Comprehensive Vulnerability Intelligence Dataset", 2024, "arXiv preprint", "https://arxiv.org/abs/2406.16347", "full_pdf"),
    ("15_vexed_by_vex_tools_arxiv_2025", "Vexed by VEX Tools: Consistency Evaluation of Container Vulnerability Scanners", 2025, "arXiv preprint", "https://arxiv.org/abs/2503.14388", "full_pdf"),
    ("16_hierarchical_selective_classification_neurips_2024", "Hierarchical Selective Classification", 2024, "NeurIPS", "https://arxiv.org/abs/2405.11533", "full_pdf"),
    ("17_nvd_versions_unreliability_2013", "The (Un)Reliability of NVD Vulnerable Versions Data", 2013, "arXiv preprint", "https://arxiv.org/abs/1302.4133", "full_pdf"),
    ("18_cvss_bayesian_tdsc_2018", "Can the Common Vulnerability Scoring System be Trusted? A Bayesian Analysis", 2018, "IEEE TDSC", "https://doi.org/10.1109/TDSC.2016.2644614", "abstract_only_closed_access"),
    ("19_automated_vulnerability_curation_tse_2023", "Empirical Validation of Automated Vulnerability Curation and Characterization", 2023, "IEEE TSE", "https://www.nist.gov/publications/empirical-validation-automated-vulnerability-curation-and-characterization", "full_pdf"),
    ("20_anatomy_vulnerability_database_jss_2023", "The Anatomy of a Vulnerability Database: A Systematic Mapping Study", 2023, "Journal of Systems and Software", "https://doi.org/10.1016/j.jss.2023.111679", "full_pdf"),
    ("21_vfcfinder_asiaccs_2024", "VFCFinder: Pairing Security Advisories and Patches", 2024, "ACM AsiaCCS", "https://bradreaves.net/publication/dler24/", "full_pdf"),
    ("22_data_quality_vulnerability_datasets_icse_2023", "Data Quality for Software Vulnerability Datasets", 2023, "ICSE", "https://conf.researchr.org/details/icse-2023/icse-2023-technical-track/45/Data-Quality-for-Software-Vulnerability-Datasets", "full_pdf"),
    ("23_learning_to_defer_icml_2020", "Consistent Estimators for Learning to Defer to an Expert", 2020, "ICML", "https://proceedings.mlr.press/v119/mozannar20b.html", "full_pdf"),
    ("24_cvefixes_promise_2021", "CVEfixes: Automated Collection of Vulnerabilities and Their Fixes from Open-Source Software", 2021, "PROMISE", "https://arxiv.org/abs/2107.08760", "full_pdf"),
]

ENTRY_EXTRAS = {
    "05_affected_versions_arxiv_2025": {
        "formal_doi": "10.1109/ASE63991.2025.00244",
        "open_pdf_source_url": "https://arxiv.org/abs/2509.03876",
        "publication_status_checked_on": "2026-08-25",
    },
    "13_ghsa_review_pipeline_arxiv_2026": {
        "formal_doi": "10.1145/3793302.3793360",
        "open_pdf_source_url": "https://arxiv.org/abs/2602.06009",
        "artifact_url": "https://github.com/cmsegal/ghsa-review",
        "publication_status_checked_on": "2026-08-25",
    },
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pdf_pages(path: Path) -> int:
    result = subprocess.run(
        ["pdfinfo", str(path)], capture_output=True, text=True, check=True
    )
    for line in result.stdout.splitlines():
        if line.startswith("Pages:"):
            return int(line.split(":", 1)[1].strip())
    raise RuntimeError(f"missing page count: {path}")


def pdf_words(path: Path) -> int:
    result = subprocess.run(
        ["pdftotext", str(path), "-"], capture_output=True, check=True
    )
    return len(result.stdout.split())


def main() -> None:
    entries = []
    for directory, title, year, venue, source_url, evidence_level in METADATA:
        paper_dir = PAPERS / directory
        report = paper_dir / "analysis_zh.md"
        report_text = report.read_text(encoding="utf-8")
        missing = [heading for heading in REQUIRED_HEADINGS if heading not in report_text]
        if missing:
            raise RuntimeError(f"{report}: missing headings {missing}")

        pdfs = sorted(paper_dir.glob("*.pdf"))
        expects_pdf = evidence_level == "full_pdf"
        if expects_pdf and len(pdfs) != 1:
            raise RuntimeError(f"{paper_dir}: expected one PDF, found {len(pdfs)}")
        if not expects_pdf and pdfs:
            raise RuntimeError(f"{paper_dir}: unexpected PDF for {evidence_level}")

        entry = {
            "id": directory,
            "title": title,
            "year": year,
            "venue": venue,
            "source_url": source_url,
            "evidence_level": evidence_level,
            "analysis_path": str(report.relative_to(ROOT)),
        }
        entry.update(ENTRY_EXTRAS.get(directory, {}))
        if pdfs:
            pdf = pdfs[0]
            entry["pdf_path"] = str(pdf.relative_to(ROOT))
            entry["pdf_bytes"] = pdf.stat().st_size
            entry["pdf_pages"] = pdf_pages(pdf)
            entry["pdf_text_words"] = pdf_words(pdf)
            entry["pdf_sha256"] = sha256(pdf)
        entries.append(entry)

    payload = {
        "schema_version": 1,
        "generated_at": "2026-08-25",
        "search_cutoff": "2026-08-24; closest-work publication status refreshed 2026-08-25",
        "scope": "NVD-GHSA field discrepancies, vulnerability metadata quality, conflict resolution, abstention/deferral, and reproducible datasets",
        "evidence_summary": {
            "papers": len(entries),
            "full_pdf": sum(e["evidence_level"] == "full_pdf" for e in entries),
            "abstract_only_closed_access": sum(
                e["evidence_level"] == "abstract_only_closed_access" for e in entries
            ),
        },
        "entries": entries,
    }
    OUTPUT.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"PASS papers={len(entries)} full_pdf={payload['evidence_summary']['full_pdf']} "
        f"abstract_only={payload['evidence_summary']['abstract_only_closed_access']}"
    )


if __name__ == "__main__":
    main()
