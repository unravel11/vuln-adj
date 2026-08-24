#!/usr/bin/env python3
"""Build the fixed non-equal artifact-lineage development cohort."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import build_artifact_lineage_development_cohort as equal_cohort


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "artifact_lineage_non_equal_cohort_v1"
DEFAULT_SOURCE = equal_cohort.DEFAULT_SOURCE
DEFAULT_OUTPUT_DIR = (
    "data/annotations/holdout/rq2_typing_v1/contract_calibration_v2/"
    "artifact_lineage_non_equal_v1"
)
PRIOR_CASE_IDS = {"rq2_typing_holdout_v1:148"}
EXPECTED_SAMPLE_IDS = (
    "rq2_typing_holdout_v1:016",
    "rq2_typing_holdout_v1:026",
    "rq2_typing_holdout_v1:086",
    "rq2_typing_holdout_v1:737",
    "rq2_typing_holdout_v1:864",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=DEFAULT_SOURCE)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def select_row(row: dict) -> dict | None:
    if row.get("sample_id") in PRIOR_CASE_IDS or row.get("field") != "affected_versions":
        return None
    nvd_value = row.get("nvd_value") or []
    ghsa_value = row.get("ghsa_value") or []
    if not nvd_value or not ghsa_value:
        return None
    nvd_subjects = equal_cohort.subjects(nvd_value)
    ghsa_subjects = equal_cohort.subjects(ghsa_value)
    if len(nvd_subjects) != 1 or len(ghsa_subjects) != 1:
        return None
    if equal_cohort.normalize_subject(nvd_subjects[0]) == equal_cohort.normalize_subject(
        ghsa_subjects[0]
    ):
        return None
    nvd_signature = equal_cohort.range_signature(nvd_value)
    ghsa_signature = equal_cohort.range_signature(ghsa_value)
    if not nvd_signature or not ghsa_signature or nvd_signature == ghsa_signature:
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
        "prior_case_ids_excluded": sorted(PRIOR_CASE_IDS),
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
            "non-equal cohort drift: "
            f"expected {EXPECTED_SAMPLE_IDS}, observed {observed}"
        )
    return selected


def main() -> int:
    args = parse_args()
    source_path = equal_cohort.resolve(args.source)
    output_dir = equal_cohort.resolve(args.output_dir)
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite sealed cohort: {output_dir}")
    cohort = build_cohort(equal_cohort.read_jsonl(source_path))
    output_dir.mkdir(parents=True, exist_ok=False)
    cohort_path = output_dir / "cohort.jsonl"
    manifest_path = output_dir / "manifest.sealed.json"
    with cohort_path.open("w", encoding="utf-8") as handle:
        for row in cohort:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "artifact_lineage_non_equal_cohort_manifest",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sealed": True,
        "source": {
            "path": str(source_path),
            "sha256": equal_cohort.sha256(source_path),
        },
        "output": {
            "path": str(cohort_path),
            "sha256": equal_cohort.sha256(cohort_path),
        },
        "selection": {
            "field": "affected_versions",
            "both_claims_nonempty": True,
            "one_subject_per_source": True,
            "full_subject_identifiers_differ": True,
            "raw_range_signatures_differ": True,
            "prior_case_ids_excluded": sorted(PRIOR_CASE_IDS),
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
    print(f"Selected {len(cohort)} non-equal rows without reviewer labels")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
