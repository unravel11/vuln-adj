#!/usr/bin/env python3
"""Render every manuscript PDF page into a compact visual-audit contact sheet."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PDF = PROJECT_ROOT / "paper/cose/latex/main.pdf"
DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "results/paper_cose/visual_checks/pdf_contact_sheet/main_contact_sheet.png"
)
DEFAULT_MANIFEST = DEFAULT_OUTPUT.with_suffix(".json")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pdf", type=Path, default=DEFAULT_PDF)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--columns", type=int, default=5)
    parser.add_argument("--thumbnail-width", type=int, default=180)
    return parser.parse_args()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def project_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return str(resolved)


def pdf_page_count(pdf_path: Path) -> int:
    result = subprocess.run(
        ["pdfinfo", str(pdf_path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"pdfinfo failed:\n{result.stdout}")
    match = re.search(r"^Pages:\s+(\d+)\s*$", result.stdout, flags=re.MULTILINE)
    if not match:
        raise RuntimeError("pdfinfo output did not contain a Pages field")
    return int(match.group(1))


def rendered_page_number(path: Path) -> int:
    match = re.search(r"-(\d+)\.png$", path.name)
    if not match:
        raise RuntimeError(f"unexpected pdftoppm output filename: {path.name}")
    return int(match.group(1))


def render_pages(pdf_path: Path, output_dir: Path, thumbnail_width: int) -> list[Path]:
    prefix = output_dir / "page"
    result = subprocess.run(
        [
            "pdftoppm",
            "-png",
            "-scale-to-x",
            str(thumbnail_width),
            "-scale-to-y",
            "-1",
            str(pdf_path),
            str(prefix),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"pdftoppm failed:\n{result.stdout}")
    return sorted(output_dir.glob("page-*.png"), key=rendered_page_number)


def build_contact_sheet(
    page_paths: list[Path],
    output_path: Path,
    *,
    columns: int,
    thumbnail_width: int,
) -> tuple[int, int]:
    if not page_paths:
        raise RuntimeError("pdftoppm produced no page images")
    if columns < 1 or thumbnail_width < 1:
        raise ValueError("columns and thumbnail width must be positive")

    with Image.open(page_paths[0]) as first:
        thumbnail_height = first.height
    gap = 8
    label_height = 20
    cell_width = thumbnail_width + gap
    cell_height = thumbnail_height + label_height + gap
    rows = (len(page_paths) + columns - 1) // columns
    sheet = Image.new(
        "RGB",
        (columns * cell_width + gap, rows * cell_height + gap),
        color=(235, 238, 242),
    )
    draw = ImageDraw.Draw(sheet)
    font = ImageFont.load_default()

    for index, page_path in enumerate(page_paths):
        page_number = rendered_page_number(page_path)
        row, column = divmod(index, columns)
        x = gap + column * cell_width
        y = gap + row * cell_height
        with Image.open(page_path) as page:
            page_rgb = page.convert("RGB")
            if page_rgb.width != thumbnail_width:
                raise RuntimeError(
                    f"unexpected page width for {page_path.name}: {page_rgb.width}"
                )
            sheet.paste(page_rgb, (x, y))
        draw.rectangle(
            (x - 1, y - 1, x + thumbnail_width, y + thumbnail_height),
            outline=(104, 112, 122),
            width=1,
        )
        draw.text(
            (x, y + thumbnail_height + 4),
            f"Page {page_number}",
            fill=(28, 32, 38),
            font=font,
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    sheet.save(output_path, format="PNG", optimize=False)
    return sheet.size


def main() -> int:
    args = parse_args()
    pdf_path = args.pdf.resolve()
    output_path = args.output.resolve()
    manifest_path = args.manifest.resolve()
    expected_pages = pdf_page_count(pdf_path)

    with tempfile.TemporaryDirectory(prefix="cose-pdf-contact-sheet-") as temp:
        page_paths = render_pages(pdf_path, Path(temp), args.thumbnail_width)
        rendered_pages = [rendered_page_number(path) for path in page_paths]
        expected_page_numbers = list(range(1, expected_pages + 1))
        if rendered_pages != expected_page_numbers:
            raise RuntimeError(
                "rendered page sequence does not cover the PDF exactly: "
                f"expected={expected_page_numbers}, observed={rendered_pages}"
            )
        dimensions = build_contact_sheet(
            page_paths,
            output_path,
            columns=args.columns,
            thumbnail_width=args.thumbnail_width,
        )

    manifest = {
        "schema_version": 1,
        "source_pdf": {
            "path": project_path(pdf_path),
            "sha256": sha256(pdf_path),
            "size_bytes": pdf_path.stat().st_size,
            "page_count": expected_pages,
        },
        "rendered_pages": rendered_pages,
        "rendered_page_count": len(rendered_pages),
        "layout": {
            "columns": args.columns,
            "rows": (len(rendered_pages) + args.columns - 1) // args.columns,
            "thumbnail_width": args.thumbnail_width,
        },
        "contact_sheet": {
            "path": project_path(output_path),
            "sha256": sha256(output_path),
            "size_bytes": output_path.stat().st_size,
            "dimensions": list(dimensions),
        },
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        f"Rendered {len(rendered_pages)} pages to {output_path} "
        f"({dimensions[0]}x{dimensions[1]})"
    )
    print(f"Wrote {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
