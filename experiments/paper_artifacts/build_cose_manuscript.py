#!/usr/bin/env python3
"""Assemble the COSE Markdown draft from section files."""

from __future__ import annotations

import argparse
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PAPER_DIR = "paper/cose"
DEFAULT_OUTPUT = "paper/cose/full_draft.md"

SECTION_FILES = (
    "title_page.md",
    "highlights.md",
    "abstract.md",
    "sections/01_introduction.md",
    "sections/02_background_problem_definition.md",
    "sections/03_method.md",
    "sections/04_experimental_setup.md",
    "sections/05_results.md",
    "sections/06_discussion.md",
    "sections/07_threats_to_validity.md",
    "sections/08_related_work.md",
    "sections/09_conclusion.md",
    "references.md",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the COSE full Markdown draft.")
    parser.add_argument("--paper-dir", default=DEFAULT_PAPER_DIR)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    return parser.parse_args()


def resolve_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return (PROJECT_ROOT / path).resolve()


def read_section(path: Path) -> str:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        raise ValueError(f"Empty manuscript section: {path}")
    return text


def title_from_title_page(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("Title:"):
            return line.split(":", 1)[1].strip()
    raise ValueError(f"Could not find title in {path}")


def main() -> int:
    args = parse_args()
    paper_dir = resolve_path(args.paper_dir)
    output_path = resolve_path(args.output)
    title = title_from_title_page(paper_dir / "title_page.md")

    parts = [
        f"# {title}",
        "",
        "Status: working manuscript assembled from logged artifacts. Baseline and silver-label results are not human gold unless explicitly stated.",
        "",
    ]
    for section_file in SECTION_FILES:
        parts.append(read_section(paper_dir / section_file))
        parts.append("")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(parts).rstrip() + "\n", encoding="utf-8")
    print(f"Wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
