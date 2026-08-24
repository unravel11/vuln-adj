#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import build_cose_latex as target


SVG = """<svg xmlns="http://www.w3.org/2000/svg" width="32" height="16">
<rect width="32" height="16" fill="#336699"/>
</svg>
"""


class ConvertFiguresTests(unittest.TestCase):
    def test_cairosvg_fallback_writes_both_pngs(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paper_dir = root / "paper"
            output_dir = root / "latex"
            (paper_dir / "figures").mkdir(parents=True)
            (output_dir / "figures").mkdir(parents=True)
            for name in ("rq1_discrepancy_heatmap", "method_framework"):
                (paper_dir / f"figures/{name}.svg").write_text(
                    SVG, encoding="utf-8"
                )
            with mock.patch.object(target.shutil, "which", return_value=None):
                target.convert_figures(paper_dir, output_dir)
            for name in ("rq1_discrepancy_heatmap", "method_framework"):
                data = (output_dir / f"figures/{name}.png").read_bytes()
                self.assertTrue(data.startswith(b"\x89PNG\r\n\x1a\n"))

    def test_missing_source_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "latex/figures").mkdir(parents=True)
            with self.assertRaises(FileNotFoundError):
                target.convert_figures(root / "paper", root / "latex")


if __name__ == "__main__":
    unittest.main()
