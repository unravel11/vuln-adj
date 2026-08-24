#!/usr/bin/env python3
"""Build the explicit evidence overlay used by the source re-audit diagnostics."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASE = (
    "data/annotations/rq3/silver_v2/"
    "affected_versions_fc_manual_check.evidence.jsonl"
)
DEFAULT_REFRESHED = (
    "data/annotations/ai_adjudicated_gold/source_reaudit/rq3_affected_versions/"
    "evidence_refresh/source_rows.evidence.jsonl"
)
DEFAULT_SELECTION = (
    "data/annotations/ai_adjudicated_gold/source_reaudit/rq3_affected_versions/"
    "selection_manifest.json"
)
DEFAULT_OUTPUT_DIR = (
    "data/annotations/ai_adjudicated_gold/source_reaudit/rq3_affected_versions/"
    "evidence_overlay"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-evidence", default=DEFAULT_BASE)
    parser.add_argument("--refreshed-evidence", action="append")
    parser.add_argument("--selection-manifest", action="append")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_jsonl(path: Path) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            sample_id = row.get("sample_id")
            if not sample_id or sample_id in rows:
                raise ValueError(f"{path}:{line_number}: invalid or duplicate sample_id")
            rows[sample_id] = row
    return rows


def main() -> int:
    args = parse_args()
    base_path = resolve(args.base_evidence)
    refreshed_paths = [
        resolve(value) for value in (args.refreshed_evidence or [DEFAULT_REFRESHED])
    ]
    selection_paths = [
        resolve(value) for value in (args.selection_manifest or [DEFAULT_SELECTION])
    ]
    if len(refreshed_paths) != len(selection_paths):
        raise ValueError("each refreshed evidence input needs one selection manifest")
    output_dir = resolve(args.output_dir)

    base = load_jsonl(base_path)
    refreshed: dict[str, dict] = {}
    selected_ids: set[str] = set()
    refreshed_inputs = []
    selection_inputs = []
    for refreshed_path, selection_path in zip(refreshed_paths, selection_paths):
        current = load_jsonl(refreshed_path)
        selection = json.loads(selection_path.read_text(encoding="utf-8"))
        current_selected = set(selection.get("sample_ids") or [])
        if set(current) != current_selected:
            raise ValueError(
                f"{refreshed_path}: IDs do not match {selection_path}"
            )
        overlap = set(refreshed) & set(current)
        if overlap:
            raise ValueError(f"refreshed evidence inputs overlap: {sorted(overlap)}")
        refreshed.update(current)
        selected_ids.update(current_selected)
        refreshed_inputs.append(
            {
                "path": str(refreshed_path),
                "sha256": sha256(refreshed_path),
                "rows": len(current),
            }
        )
        selection_inputs.append(
            {
                "path": str(selection_path),
                "sha256": sha256(selection_path),
                "rows": len(current_selected),
            }
        )
    if len(base) != 100:
        raise ValueError(f"expected 100 base evidence rows, found {len(base)}")
    if not selected_ids <= set(base):
        raise ValueError("selection contains IDs missing from base evidence")

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "affected_versions_source_evidence_overlay.jsonl"
    manifest_path = output_dir / "affected_versions_source_evidence_overlay_manifest.json"
    with output_path.open("w", encoding="utf-8") as handle:
        for sample_id in sorted(base):
            row = refreshed.get(sample_id, base[sample_id])
            if row.get("cve_id") != base[sample_id].get("cve_id"):
                raise ValueError(f"{sample_id}: refreshed CVE mapping changed")
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    manifest = {
        "artifact_type": "affected_versions_source_evidence_overlay",
        "rows": len(base),
        "base_rows": len(base) - len(refreshed),
        "refreshed_rows": len(refreshed),
        "selection_uses_ai_gold_status": True,
        "feature_input_is_selection_aware": True,
        "label_is_human": False,
        "eligible_for_independent_holdout_claim": False,
        "inputs": {
            "base_evidence": {"path": str(base_path), "sha256": sha256(base_path)},
            "refreshed_evidence": refreshed_inputs,
            "selection_manifests": selection_inputs,
        },
        "output": {"path": str(output_path), "sha256": sha256(output_path)},
        "caution": (
            f"The {len(refreshed)} refreshed rows were selected using prior "
            "AI-gold status. "
            "This overlay is suitable for source-reaudit diagnostics, not an "
            "independent holdout claim."
        ),
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
