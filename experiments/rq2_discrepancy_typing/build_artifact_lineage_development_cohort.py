#!/usr/bin/env python3
"""Build a label-independent cross-case cohort for artifact-lineage auditing."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "artifact_lineage_development_cohort_v1"
DEFAULT_SOURCE = (
    "data/annotations/holdout/rq2_typing_v1/contract_calibration_v2/source_rows.jsonl"
)
DEFAULT_OUTPUT_DIR = (
    "data/annotations/holdout/rq2_typing_v1/contract_calibration_v2/"
    "artifact_lineage_cross_case_v1"
)
EXPECTED_SAMPLE_IDS = (
    "rq2_typing_holdout_v1:006",
    "rq2_typing_holdout_v1:154",
    "rq2_typing_holdout_v1:212",
    "rq2_typing_holdout_v1:461",
    "rq2_typing_holdout_v1:587",
    "rq2_typing_holdout_v1:615",
    "rq2_typing_holdout_v1:1149",
    "rq2_typing_holdout_v1:1173",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=DEFAULT_SOURCE)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            row["_input_line_number"] = line_number
            rows.append(row)
    return rows


def normalize_subject(value: str) -> str:
    return re.sub(r"\\+", "", value.strip().lower())


def cpe_release(record: dict) -> str | None:
    criteria = str(record.get("criteria") or "")
    parts = criteria.split(":")
    if len(parts) < 7:
        return None
    version, update = parts[5], parts[6]
    if version in {"", "*", "-"}:
        return None
    if update in {"", "*", "-"}:
        return version
    token = update.lower().replace("_", "-")
    token = re.sub(r"^(alpha|beta|rc|milestone)-?(\d+)$", r"\1-\2", token)
    return f"{version}-{token}"


def record_span(record: dict) -> dict | None:
    start = record.get("version_start_including") or record.get("introduced")
    start_inclusive = True
    if record.get("version_start_excluding"):
        start = record["version_start_excluding"]
        start_inclusive = False

    end = record.get("version_end_excluding") or record.get("fixed")
    end_inclusive = False
    if record.get("version_end_including"):
        end = record["version_end_including"]
        end_inclusive = True

    point = cpe_release(record)
    has_range = bool(start or end)
    if point and not has_range:
        return {
            "start": point,
            "start_inclusive": True,
            "end": point,
            "end_inclusive": True,
            "kind": "point",
        }
    if not start and not end:
        return None
    return {
        "start": str(start or "0"),
        "start_inclusive": start_inclusive,
        "end": str(end) if end is not None else None,
        "end_inclusive": end_inclusive,
        "kind": "range",
    }


def range_signature(records: list[dict]) -> list[dict]:
    spans = [span for record in records if (span := record_span(record))]
    return sorted(
        spans,
        key=lambda item: (
            item["start"],
            item["end"] or "",
            item["start_inclusive"],
            item["end_inclusive"],
            item["kind"],
        ),
    )


def subjects(records: list[dict]) -> list[str]:
    return sorted(
        {
            str(record.get("product") or record.get("package_name"))
            for record in records
            if record.get("product") or record.get("package_name")
        }
    )


def select_row(row: dict) -> dict | None:
    if row.get("field") != "affected_versions":
        return None
    nvd_value = row.get("nvd_value") or []
    ghsa_value = row.get("ghsa_value") or []
    if not nvd_value or not ghsa_value:
        return None
    nvd_subjects = subjects(nvd_value)
    ghsa_subjects = subjects(ghsa_value)
    if len(nvd_subjects) != 1 or len(ghsa_subjects) != 1:
        return None
    if normalize_subject(nvd_subjects[0]) == normalize_subject(ghsa_subjects[0]):
        return None
    nvd_signature = range_signature(nvd_value)
    ghsa_signature = range_signature(ghsa_value)
    if not nvd_signature or nvd_signature != ghsa_signature:
        return None
    return {
        "schema_version": SCHEMA_VERSION,
        "sample_id": row["sample_id"],
        "cve_id": row["cve_id"],
        "field": row["field"],
        "nvd_subject": nvd_subjects[0],
        "ghsa_subject": ghsa_subjects[0],
        "nvd_range_signature": nvd_signature,
        "ghsa_range_signature": ghsa_signature,
        "nvd_value": nvd_value,
        "ghsa_value": ghsa_value,
        "reference_context": row.get("reference_context") or {},
        "source_line_number": row.get("source_line_number")
        or row.get("_input_line_number"),
        "selection_uses_reviewer_labels": False,
        "selection_uses_non_human_consensus": False,
        "upstream_source_conditioned_on_non_human_consensus": True,
        "development_diagnostic_only": True,
        "post_unsealing": True,
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
    }


def build_cohort(rows: list[dict]) -> list[dict]:
    selected = [candidate for row in rows if (candidate := select_row(row))]
    selected.sort(key=lambda row: int(row["sample_id"].rsplit(":", 1)[1]))
    observed = tuple(row["sample_id"] for row in selected)
    if observed != EXPECTED_SAMPLE_IDS:
        raise ValueError(
            "cross-case cohort drift: "
            f"expected {EXPECTED_SAMPLE_IDS}, observed {observed}"
        )
    return selected


def main() -> int:
    args = parse_args()
    source_path = resolve(args.source)
    output_dir = resolve(args.output_dir)
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite sealed cohort: {output_dir}")
    cohort = build_cohort(read_jsonl(source_path))
    output_dir.mkdir(parents=True, exist_ok=False)
    cohort_path = output_dir / "cohort.jsonl"
    manifest_path = output_dir / "manifest.sealed.json"
    with cohort_path.open("w", encoding="utf-8") as handle:
        for row in cohort:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "artifact_lineage_development_cohort_manifest",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sealed": True,
        "source": {"path": str(source_path), "sha256": sha256(source_path)},
        "output": {"path": str(cohort_path), "sha256": sha256(cohort_path)},
        "selection": {
            "field": "affected_versions",
            "both_claims_nonempty": True,
            "one_subject_per_source": True,
            "full_subject_identifiers_differ": True,
            "raw_range_signatures_equal": True,
            "selection_uses_reviewer_labels": False,
            "selection_uses_non_human_consensus": False,
            "upstream_source_conditioned_on_non_human_consensus": True,
        },
        "selected_count": len(cohort),
        "selected_sample_ids": [row["sample_id"] for row in cohort],
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "development_diagnostic_only": True,
        "post_unsealing": True,
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {cohort_path}")
    print(f"Selected {len(cohort)} cross-case rows without reviewer labels")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
