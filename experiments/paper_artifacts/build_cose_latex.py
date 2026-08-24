#!/usr/bin/env python3
"""Build an Elsevier/elsarticle LaTeX scaffold from the COSE Markdown draft."""

from __future__ import annotations

import argparse
import csv
import re
import shutil
import subprocess
import unicodedata
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PAPER_DIR = "paper/cose"
DEFAULT_OUTPUT_DIR = "paper/cose/latex"

SECTION_FILES = (
    "sections/01_introduction.md",
    "sections/02_background_problem_definition.md",
    "sections/03_method.md",
    "sections/04_experimental_setup.md",
    "sections/05_results.md",
    "sections/06_discussion.md",
    "sections/07_threats_to_validity.md",
    "sections/08_related_work.md",
    "sections/09_conclusion.md",
)

TABLE_CAPTIONS = {
    ("05_results", "Field-level discrepancy baseline", 1): (
        "Deterministic baseline discrepancy distribution over 8,066 aligned "
        "NVD-GHSA pairs. Counts are baseline outputs, not gold labels."
    ),
    ("05_results", "Severity silver-label diagnostic comparison", 1): (
        "Severity source-adjudication baselines compared against the "
        "80-sample evidence-aware silver-v2 label set. Values are silver-label "
        "diagnostics, not human-gold performance."
    ),
    ("05_results", "Affected_versions silver-label distribution", 1): (
        "Affected_versions evidence-aware silver-label distribution for the "
        "100-sample manual-check set."
    ),
    ("05_results", "Affected_versions silver-label distribution", 2): (
        "Affected_versions adjudicated-source distribution in the evidence-aware "
        "silver label set."
    ),
    ("05_results", "Affected_versions silver-label diagnostic comparison", 1): (
        "Affected_versions source-adjudication baselines compared against the "
        "100-sample evidence-aware silver-v2 label set. Values are silver-label "
        "diagnostics, not human-gold performance."
    ),
    ("03_method", "", 1): (
        "Method contract for routing field discrepancies before source-support "
        "adjudication. Validation boundaries reflect the current validation state."
    ),
    ("03_method", "Operational input/output contract", 1): (
        "Operational input/output contract for the implemented method stages. "
        "Validation boundaries reflect the current validation state."
    ),
    ("03_method", "Procedure overview", 1): (
        "Procedure 1: field-view construction and deterministic discrepancy "
        "typing over aligned field instances."
    ),
    ("03_method", "Procedure overview", 2): (
        "Procedure 2: evidence-constrained source-support prototype for sampled "
        "factual-conflict instances."
    ),
    ("03_method", "Discrepancy typing", 1): (
        "Ordered field-specific baseline rule paths for discrepancy typing. "
        "The rules are diagnostic until RQ2 human labels exist."
    ),
    ("03_method", "Discrepancy typing", 2): (
        "Illustrative baseline routing examples. These examples explain method "
        "behavior and are not gold labels."
    ),
    ("03_method", "Evidence-constrained adjudication prototype", 1): (
        "Source-support decision labels used by the RQ3 prototype and human "
        "audit handoff."
    ),
    ("03_method", "Audit interface and current boundary", 1): (
        "Mapping between research questions, method stages, current evidence, "
        "and claim boundaries."
    ),
    ("08_related", "", 1): (
        "Reviewer-facing boundary between this paper and neighboring lines of "
        "work. The current contribution is a post-alignment structured-field "
        "typing workflow with an evidence-constrained adjudication scaffold."
    ),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the COSE LaTeX scaffold.")
    parser.add_argument("--paper-dir", default=DEFAULT_PAPER_DIR)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return (PROJECT_ROOT / path).resolve()


def latex_escape(value: str) -> str:
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
        "<": r"\textless{}",
        ">": r"\textgreater{}",
    }
    return "".join(replacements.get(char, char) for char in value)


def format_inline(value: str) -> str:
    tokens: list[str] = []

    def stash(raw: str) -> str:
        tokens.append(raw)
        return f"ZZLATEXTOKEN{len(tokens) - 1}ZZ"

    def code_repl(match: re.Match[str]) -> str:
        raw = match.group(1)
        if "/" in raw or len(raw) > 28:
            return stash(r"\path{" + raw.replace("\\", "/").replace("}", r"\}") + "}")
        return stash(r"\texttt{" + latex_escape(raw) + "}")

    def cite_repl(match: re.Match[str]) -> str:
        return stash(r"\cite{" + match.group(1) + "}")

    def emph_repl(match: re.Match[str]) -> str:
        return stash(r"\emph{" + latex_escape(match.group(1)) + "}")

    text = re.sub(r"`([^`]+)`", code_repl, value)
    text = re.sub(r"\[([A-Za-z][A-Za-z0-9]+(?:\s*,\s*[A-Za-z][A-Za-z0-9]+)*)\]", cite_repl, text)
    text = re.sub(r"\*([^*\n]+)\*", emph_repl, text)
    text = latex_escape(text)
    for index, token in enumerate(tokens):
        text = text.replace(f"ZZLATEXTOKEN{index}ZZ", token)
    return text


def parse_markdown_table(lines: list[str]) -> list[list[str]]:
    rows: list[list[str]] = []
    for line in lines:
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if all(set(cell.replace(":", "").replace(" ", "")) <= {"-"} for cell in cells):
            continue
        rows.append(cells)
    return rows


def is_numericish(value: str) -> bool:
    return bool(re.fullmatch(r"[-0-9,().% ]+", value.strip()))


def render_table(
    rows: list[list[str]],
    *,
    section_slug: str,
    subsection: str,
    table_number: int,
) -> list[str]:
    if not rows:
        return []
    ncols = max(len(row) for row in rows)
    rows = [row + [""] * (ncols - len(row)) for row in rows]
    body = rows[1:]
    long_table = ncols > 3 or any(len(cell) > 28 for row in rows for cell in row)
    caption = TABLE_CAPTIONS.get(
        (section_slug, subsection, table_number),
        f"Generated table from {subsection or section_slug}.",
    )
    label = f"tab:{section_slug.replace('_', '-')}-{slugify(subsection)}-{table_number}"

    if long_table:
        first_width = "0.18\\textwidth" if ncols <= 6 else "0.15\\textwidth"
        colspec = (
            r">{\raggedright\arraybackslash}p{" + first_width + "}"
            + "".join(r">{\raggedright\arraybackslash}X" for _ in range(ncols - 1))
        )
        begin = [
            r"\begin{table}[!htbp]",
            r"\centering",
            r"\setlength{\tabcolsep}{3pt}",
            r"\footnotesize" if ncols <= 4 else r"\scriptsize",
        ]
        begin.append(r"\caption{" + format_inline(caption) + "}")
        begin.append(r"\label{" + label + "}")
        begin.append(r"\begin{tabularx}{\textwidth}{" + colspec + "}")
        end = [r"\bottomrule", r"\end{tabularx}", r"\end{table}"]
    else:
        numeric_cols = [
            all(is_numericish(row[index]) for row in body) for index in range(ncols)
        ]
        colspec = "".join("r" if numeric_cols[index] else "l" for index in range(ncols))
        begin = [r"\begin{table}[!htbp]", r"\centering"]
        begin.append(r"\caption{" + format_inline(caption) + "}")
        begin.append(r"\label{" + label + "}")
        begin.append(r"\begin{tabular}{" + colspec + "}")
        end = [r"\bottomrule", r"\end{tabular}", r"\end{table}"]

    rendered = begin + [r"\toprule"]
    rendered.append(" & ".join(format_inline(cell) for cell in rows[0]) + r" \\")
    rendered.append(r"\midrule")
    for row in rows[1:]:
        rendered.append(" & ".join(format_inline(cell) for cell in row) + r" \\")
    rendered.extend(end)
    return rendered


def slugify(value: str) -> str:
    value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    value = re.sub(r"[^a-zA-Z0-9]+", "-", value.lower()).strip("-")
    return value or "table"


def figure_block() -> list[str]:
    return [
        r"\begin{figure}[!htbp]",
        r"\centering",
        r"\includegraphics[width=\textwidth]{figures/rq1_discrepancy_heatmap.png}",
        (
            r"\caption{Field by discrepancy-type heatmap for the deterministic "
            r"baseline over 8,066 aligned NVD-GHSA pairs. Counts are baseline "
            r"outputs, not gold labels.}"
        ),
        r"\label{fig:rq1-discrepancy-heatmap}",
        r"\end{figure}",
        "",
    ]


def method_framework_block() -> list[str]:
    return [
        r"\begin{figure}[!htbp]",
        r"\centering",
        r"\includegraphics[width=\textwidth]{figures/method_framework.png}",
        (
            r"\caption{Method framework for post-alignment NVD-GHSA field "
            r"discrepancy typing and evidence-constrained adjudication. The "
            r"adjudication stage is currently a silver-label prototype, not a "
            r"human-gold source-truth result.}"
        ),
        r"\label{fig:method-framework}",
        r"\end{figure}",
        "",
    ]


def convert_markdown_section(path: Path) -> str:
    section_slug = path.stem[:10].strip("-")
    lines = path.read_text(encoding="utf-8").splitlines()
    output: list[str] = []
    paragraph: list[str] = []
    current_subsection = ""
    table_counts: dict[str, int] = {}
    in_items = False

    def flush_paragraph() -> None:
        if paragraph:
            output.append(format_inline(" ".join(part.strip() for part in paragraph)))
            output.append("")
            paragraph.clear()

    def close_items() -> None:
        nonlocal in_items
        if in_items:
            output.append(r"\end{itemize}")
            output.append("")
            in_items = False

    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if not stripped:
            flush_paragraph()
            close_items()
            index += 1
            continue

        if stripped.startswith("|") and "|" in stripped[1:]:
            flush_paragraph()
            close_items()
            table_lines = []
            while index < len(lines) and lines[index].strip().startswith("|"):
                table_lines.append(lines[index])
                index += 1
            table_counts[current_subsection] = table_counts.get(current_subsection, 0) + 1
            output.extend(
                render_table(
                    parse_markdown_table(table_lines),
                    section_slug=section_slug,
                    subsection=current_subsection,
                    table_number=table_counts[current_subsection],
                )
            )
            output.append("")
            continue

        if stripped.startswith("#"):
            flush_paragraph()
            close_items()
            level = len(stripped) - len(stripped.lstrip("#"))
            title = stripped[level:].strip()
            if level == 1:
                output.append(r"\section{" + format_inline(title) + "}")
                if path.name == "03_method.md":
                    output.append("")
                    output.extend(method_framework_block())
            elif level == 2:
                current_subsection = title
                output.append(r"\subsection{" + format_inline(title) + "}")
                if title == "Field-level discrepancy baseline":
                    output.extend(figure_block())
            else:
                output.append(r"\subsubsection{" + format_inline(title) + "}")
            output.append("")
            index += 1
            continue

        if stripped.startswith("- "):
            flush_paragraph()
            if not in_items:
                output.append(r"\begin{itemize}")
                in_items = True
            output.append(r"\item " + format_inline(stripped[2:].strip()))
            index += 1
            continue

        paragraph.append(stripped)
        index += 1

    flush_paragraph()
    close_items()
    return "\n".join(output).rstrip() + "\n"


def title_from_title_page(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("Title:"):
            return line.split(":", 1)[1].strip()
    raise ValueError(f"Could not find title in {path}")


def abstract_and_keywords(path: Path) -> tuple[str, list[str]]:
    abstract_lines: list[str] = []
    keywords: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("Keywords:"):
            keywords = [item.strip() for item in stripped.split(":", 1)[1].split(";")]
        else:
            abstract_lines.append(stripped)
    return " ".join(abstract_lines), keywords


def read_highlights(path: Path) -> list[str]:
    return [
        line.strip()[2:].strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("- ")
    ]


def write_standalone_table_from_csv(csv_path: Path, output_path: Path, caption: str, label: str) -> None:
    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.reader(handle))
    rendered = render_table(
        rows,
        section_slug=label.replace("tab:", "").replace("-", "_"),
        subsection=caption,
        table_number=1,
    )
    # Replace generated caption/label with the stable standalone identifiers.
    rendered = [
        r"\caption{" + format_inline(caption) + "}"
        if line.startswith(r"\caption{")
        else r"\label{" + label + "}"
        if line.startswith(r"\label{")
        else line
        for line in rendered
    ]
    output_path.write_text("\n".join(rendered).rstrip() + "\n", encoding="utf-8")


def convert_figures(paper_dir: Path, output_dir: Path) -> None:
    convert = shutil.which("convert")
    for name in ("rq1_discrepancy_heatmap", "method_framework"):
        source = paper_dir / f"figures/{name}.svg"
        target = output_dir / f"figures/{name}.png"
        if not source.exists():
            raise FileNotFoundError(source)
        if convert:
            subprocess.run([convert, str(source), str(target)], check=True)
            continue
        try:
            import cairosvg
        except ImportError as exc:
            raise RuntimeError(
                "SVG conversion requires ImageMagick convert or CairoSVG; "
                "install experiments/paper_artifacts/requirements.txt"
            ) from exc
        cairosvg.svg2png(url=str(source), write_to=str(target))


def write_main_tex(paper_dir: Path, output_dir: Path) -> None:
    title = title_from_title_page(paper_dir / "title_page.md")
    abstract, keywords = abstract_and_keywords(paper_dir / "abstract.md")
    highlights = read_highlights(paper_dir / "highlights.md")
    section_inputs = [
        f"\\input{{sections/{Path(section_file).stem}.tex}}" for section_file in SECTION_FILES
    ]

    parts = [
        r"\documentclass[preprint,review,12pt]{elsarticle}",
        "",
        r"\usepackage[T1]{fontenc}",
        r"\usepackage[utf8]{inputenc}",
        r"\usepackage{graphicx}",
        r"\usepackage{booktabs}",
        r"\usepackage{tabularx}",
        r"\usepackage{array}",
        r"\usepackage{url}",
        r"\usepackage{xurl}",
        r"\usepackage{textcomp}",
        r"\usepackage{float}",
        r"\usepackage[margin=1in]{geometry}",
        r"\emergencystretch=3em",
        r"\sloppy",
        "",
        r"\journal{Computers \& Security}",
        "",
        r"\begin{document}",
        "",
        r"\begin{frontmatter}",
        r"\title{" + format_inline(title) + "}",
        r"\author{TODO Author}",
        r"\address{TODO affiliation}",
        r"\begin{abstract}",
        format_inline(abstract),
        r"\end{abstract}",
        r"\begin{keyword}",
        r" \sep ".join(format_inline(keyword) for keyword in keywords),
        r"\end{keyword}",
        r"\end{frontmatter}",
        "",
        r"\section*{Highlights}",
        r"\begin{itemize}",
        *[r"\item " + format_inline(item) for item in highlights],
        r"\end{itemize}",
        "",
        r"\section*{Draft Status and Claim Boundaries}",
        (
            "This generated LaTeX source is a packaging scaffold produced from the "
            "Markdown manuscript and logged artifacts. RQ1 results are deterministic "
            "baseline distributions, RQ2 remains a non-gold rule-trigger diagnostic "
            "with blank annotation templates, and RQ3 results are silver-label "
            "prototype evaluations rather than human-gold performance claims."
        ),
        "",
        *section_inputs,
        "",
        r"\input{sections/declarations.tex}",
        "",
        r"\bibliographystyle{elsarticle-num}",
        r"\bibliography{references}",
        "",
        r"\end{document}",
        "",
    ]
    (output_dir / "main.tex").write_text("\n".join(parts), encoding="utf-8")


def write_makefile(output_dir: Path) -> None:
    text = """PDF=main.pdf

all:
\tlatexmk -pdf -interaction=nonstopmode -halt-on-error main.tex

clean:
\tlatexmk -C main.tex
"""
    (output_dir / "Makefile").write_text(text, encoding="utf-8")


def write_readme(output_dir: Path) -> None:
    text = """# COSE LaTeX Scaffold

This directory is generated from the Markdown manuscript and paper artifacts.
Markdown remains the source of record; rerun the generator after editing sections.

Build from the repository root:

```bash
.venv/bin/python -m pip install -r experiments/paper_artifacts/requirements.txt
.venv/bin/python experiments/paper_artifacts/build_cose_bibtex.py
.venv/bin/python experiments/paper_artifacts/build_cose_latex.py
cd paper/cose/latex
latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex
```

Claim boundaries to preserve:

- RQ1 is a deterministic baseline distribution, not a gold distribution.
- RQ2 is a diagnostic plus blank annotation templates until human labels exist.
- RQ3 uses evidence-aware silver labels, not human gold.
- `affected_versions` is currently a token-support prototype, not semantic version adjudication.
- Journal policy and generative-AI use remain author-review and declaration items.
"""
    (output_dir / "README.md").write_text(text, encoding="utf-8")


def main() -> int:
    args = parse_args()
    paper_dir = resolve_path(args.paper_dir)
    output_dir = resolve_path(args.output_dir)
    sections_dir = output_dir / "sections"
    tables_dir = output_dir / "tables"
    figures_dir = output_dir / "figures"
    for path in (sections_dir, tables_dir, figures_dir):
        path.mkdir(parents=True, exist_ok=True)

    for section_file in SECTION_FILES:
        source = paper_dir / section_file
        target = sections_dir / f"{Path(section_file).stem}.tex"
        target.write_text(convert_markdown_section(source), encoding="utf-8")

    declarations_tex = convert_markdown_section(paper_dir / "declarations.md").replace(
        r"\section{Submission Declarations Draft}",
        r"\section*{Submission Declarations Draft}",
        1,
    )
    (sections_dir / "declarations.tex").write_text(declarations_tex, encoding="utf-8")

    write_standalone_table_from_csv(
        paper_dir / "tables/rq1_discrepancy_distribution.csv",
        tables_dir / "rq1_discrepancy_distribution.tex",
        "Deterministic baseline discrepancy distribution over 8,066 aligned pairs.",
        "tab:rq1-discrepancy-distribution",
    )
    write_standalone_table_from_csv(
        paper_dir / "tables/rq3_case_study_sketches.csv",
        tables_dir / "rq3_case_study_sketches.tex",
        "RQ3 silver-label case-study sketches selected from current artifacts.",
        "tab:rq3-case-study-sketches",
    )

    shutil.copy2(paper_dir / "references.bib", output_dir / "references.bib")
    convert_figures(paper_dir, output_dir)
    write_main_tex(paper_dir, output_dir)
    write_makefile(output_dir)
    write_readme(output_dir)
    print(f"Wrote LaTeX scaffold to {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
