#!/usr/bin/env python3
"""Build a draft BibTeX file from the COSE references Markdown."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REFERENCES = "paper/cose/references.md"
DEFAULT_OUTPUT = "paper/cose/references.bib"

ENTRY_TYPES = {
    "CVE2026": "misc",
    "NVDAPI2026": "misc",
    "NVDProcess2026": "misc",
    "NVDStatus2026": "misc",
    "NVDTransition2024": "misc",
    "NVDOperations2026": "misc",
    "GHSA2026": "misc",
    "GHSAAbout2026": "misc",
    "GHSARepo2026": "misc",
    "CVSS31": "misc",
    "CWE2026": "misc",
    "OSVSchema2026": "misc",
    "VIEM2019": "inproceedings",
    "Croft2022": "inproceedings",
    "Anwar2022": "article",
    "Zhang2023": "inproceedings",
    "Wunder2024": "inproceedings",
    "NVDUsers2024": "article",
    "Chen2025AffectedVersions": "misc",
    "Sun2023": "article",
    "Wang2025Aspects": "inproceedings",
    "Li2025VuldiffFinder": "article",
    "GapFinder2021": "article",
    "CRH2016": "article",
    "Wang2024TruthSurvey": "article",
    "Segal2026GHSA": "misc",
    "Ruan2024VulZoo": "misc",
    "Churakova2026VEX": "misc",
    "Goren2024HSC": "misc",
    "Mandl2026VulnDetection": "misc",
}

VENUE_FIELDS = {
    "VIEM2019": ("booktitle", "USENIX Security Symposium"),
    "Croft2022": (
        "booktitle",
        "IEEE International Conference on Software Analysis, Evolution and Reengineering (SANER)",
    ),
    "Anwar2022": ("journal", "IEEE Transactions on Dependable and Secure Computing"),
    "Zhang2023": (
        "booktitle",
        "IEEE International Conference on Cloud Computing Technology and Science (CloudCom)",
    ),
    "Wunder2024": ("booktitle", "IEEE Symposium on Security and Privacy"),
    "NVDUsers2024": ("journal", "Digital Threats: Research and Practice"),
    "Sun2023": ("journal", "ACM Transactions on Software Engineering and Methodology"),
    "Wang2025Aspects": (
        "booktitle",
        "Proceedings of the Workshop on Privacy in Large Language Models (LLM) and Natural Language Processing (NLP) 2025",
    ),
    "Li2025VuldiffFinder": ("journal", "Computers & Security"),
    "GapFinder2021": ("journal", "IEEE Transactions on Information Forensics and Security"),
    "CRH2016": ("journal", "IEEE Transactions on Knowledge and Data Engineering"),
    "Wang2024TruthSurvey": ("journal", "IEEE Transactions on Big Data"),
}

VOLUME_NUMBER_PAGES = {
    "VIEM2019": {"pages": "869--885"},
    "Croft2022": {"pages": "338--348"},
    "Anwar2022": {"volume": "19", "number": "6", "pages": "4255--4269"},
    "Zhang2023": {"pages": "185--192"},
    "Wunder2024": {"pages": "1102--1121"},
    "NVDUsers2024": {"volume": "5", "number": "3", "pages": "1--19", "articleno": "33"},
    "Sun2023": {"volume": "33", "number": "2", "pages": "1--38", "articleno": "49"},
    "Wang2025Aspects": {"pages": "13--24"},
    "Li2025VuldiffFinder": {"volume": "154", "articleno": "104447"},
    "GapFinder2021": {"volume": "16", "pages": "86--99"},
    "CRH2016": {"volume": "28", "number": "8", "pages": "1986--1999"},
    "Wang2024TruthSurvey": {"volume": "11", "number": "2", "pages": "314--332"},
}

REFERENCE_RE = re.compile(r'^- \[(?P<key>[^\]]+)\] (?P<body>.+)$')
QUOTED_TITLE_RE = re.compile(r'"(?P<title>[^"]+)"')
ACCESSED_RE = re.compile(r"Accessed (?P<accessed>\d{4}-\d{2}-\d{2})\. (?P<url>\S+)")
ARXIV_RE = re.compile(r"arXiv:(?P<arxiv>[0-9.]+)")
DOI_RE = re.compile(r"DOI: (?P<doi>\S+)\.?$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build draft COSE BibTeX.")
    parser.add_argument("--references", default=DEFAULT_REFERENCES)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    return parser.parse_args()


def resolve_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return (PROJECT_ROOT / path).resolve()


def bib_escape(value: str) -> str:
    return (
        value.replace("\\", "\\textbackslash{}")
        .replace("&", "\\&")
    )


def parse_reference_lines(path: Path) -> list[tuple[str, str]]:
    refs = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = REFERENCE_RE.match(line.strip())
        if match:
            refs.append((match.group("key"), match.group("body")))
    return refs


def split_body(body: str) -> tuple[str, str, str]:
    title_match = QUOTED_TITLE_RE.search(body)
    if not title_match:
        raise ValueError(f"Reference body has no quoted title: {body}")
    author = body[: title_match.start()].strip()
    title = title_match.group("title").strip().rstrip(".")
    rest = body[title_match.end() :].strip()
    if rest.startswith("."):
        rest = rest[1:].strip()
    return author, title, rest


def year_from_key_or_text(key: str, text: str) -> str:
    key_match = re.search(r"(20\d{2})", key)
    if key_match:
        return key_match.group(1)
    text_match = re.search(r"(20\d{2})", text)
    if text_match:
        return text_match.group(1)
    raise ValueError(f"Could not infer year for {key}")


def source_entry(key: str, body: str) -> dict[str, str]:
    author, title, rest = split_body(body)
    accessed_match = ACCESSED_RE.search(rest)
    fields = {
        "author": format_authors(author.rstrip(".")),
        "title": title,
        "year": year_from_key_or_text(key, rest),
    }
    if accessed_match:
        fields["url"] = accessed_match.group("url")
        fields["note"] = f"Accessed: {accessed_match.group('accessed')}"
    arxiv_match = ARXIV_RE.search(rest)
    if arxiv_match:
        fields["eprint"] = arxiv_match.group("arxiv").rstrip(".")
        fields["archivePrefix"] = "arXiv"
    if not accessed_match and not arxiv_match:
        raise ValueError(f"Misc entry missing URL/access date or arXiv identifier: {key}")
    return fields


def literature_entry(key: str, body: str) -> dict[str, str]:
    author, title, rest = split_body(body)
    fields = {
        "author": format_authors(author.rstrip(".")),
        "title": title,
        "year": year_from_key_or_text(key, rest),
    }
    venue_field = VENUE_FIELDS.get(key)
    if venue_field:
        fields[venue_field[0]] = venue_field[1]
    fields.update(VOLUME_NUMBER_PAGES.get(key, {}))
    doi_match = DOI_RE.search(rest)
    if doi_match:
        fields["doi"] = doi_match.group("doi").rstrip(".")
    return fields


def format_authors(author: str) -> str:
    if author in {
        "CVE Program",
        "National Institute of Standards and Technology",
        "GitHub",
        "FIRST",
        "MITRE",
        "Open Source Vulnerabilities",
    }:
        return "{" + author + "}"
    if " et al" in author:
        return author.replace(", et al", " and others").replace(" et al.", " and others")
    if ", and " in author:
        author = author.replace(", and ", ", ")
    return author.replace(", ", " and ")


def build_entries(refs: list[tuple[str, str]]) -> list[tuple[str, str, dict[str, str]]]:
    entries = []
    for key, body in refs:
        entry_type = ENTRY_TYPES.get(key)
        if not entry_type:
            raise ValueError(f"Missing BibTeX entry type for {key}")
        fields = source_entry(key, body) if entry_type == "misc" else literature_entry(key, body)
        entries.append((entry_type, key, fields))
    return entries


def render_entry(entry_type: str, key: str, fields: dict[str, str]) -> str:
    field_lines = []
    for field, value in fields.items():
        field_lines.append(f"  {field} = {{{bib_escape(value)}}},")
    return "\n".join([f"@{entry_type}{{{key},", *field_lines, "}"])


def main() -> int:
    args = parse_args()
    references_path = resolve_path(args.references)
    output_path = resolve_path(args.output)
    entries = build_entries(parse_reference_lines(references_path))
    text = "\n\n".join(render_entry(*entry) for entry in entries) + "\n"
    output_path.write_text(text, encoding="utf-8")
    print(f"Wrote {output_path} ({len(entries)} entries)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
