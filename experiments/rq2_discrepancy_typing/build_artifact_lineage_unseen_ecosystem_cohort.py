#!/usr/bin/env python3
"""Build a label-independent heterogeneous multi-package cohort by ecosystem."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from collections import defaultdict
from pathlib import Path

import analyze_artifact_lineage_non_equal as lineage
import build_artifact_lineage_development_cohort as cohort_util


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "artifact_lineage_unseen_ecosystem_cohort_v1"
DEFAULT_SOURCE = "data/processed/bootstrap/aligned/nvd_ghsa_by_cve.jsonl"
DEFAULT_OUTPUT_DIR = (
    "data/annotations/holdout/rq2_typing_v1/contract_calibration_v2/"
    "artifact_lineage_unseen_ecosystem_v1"
)
TARGET_ECOSYSTEMS = ("NuGet", "PyPI", "crates.io")
MAX_SPANS_PER_CLAIM = 3
EXPECTED_CVES = {
    "NuGet": "CVE-2023-21893",
    "PyPI": "CVE-2023-39631",
    "crates.io": "CVE-2025-48888",
}


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


def subject(record: dict) -> str:
    return str(record.get("package_name") or record.get("product") or "").strip()


def vulnerable_records(records: list[dict]) -> list[dict]:
    return [record for record in records if record.get("vulnerable") is not False]


def flattened_ghsa_affected(row: dict) -> list[dict]:
    return vulnerable_records(
        [record for advisory in row.get("ghsa") or [] for record in advisory.get("affected") or []]
    )


def canonical_signature(records: list[dict]) -> tuple:
    spans = cohort_util.range_signature(records)
    return tuple(
        sorted(
            (
                span["start"],
                span["start_inclusive"],
                span["end"] or "",
                span["end_inclusive"],
                span["kind"],
            )
            for span in spans
        )
    )


def boundaries_parse(signatures: list[list[dict]]) -> bool:
    for signature in signatures:
        for span in signature:
            for value in (span.get("start"), span.get("end")):
                if value and value != "0" and lineage.normalized_version(str(value)) is None:
                    return False
    return True


def reference_urls(records: list[dict]) -> list[str]:
    return sorted(
        {
            str(item.get("url") or "")
            for record in records
            for item in record.get("references") or []
            if item.get("url")
        }
    )


def eligible_row(row: dict) -> dict | None:
    if not row.get("ghsa"):
        return None
    nvd_records = vulnerable_records((row.get("nvd") or {}).get("affected") or [])
    ghsa_records = flattened_ghsa_affected(row)
    nvd_subjects = sorted({subject(record) for record in nvd_records if subject(record)})
    ghsa_subjects = sorted({subject(record) for record in ghsa_records if subject(record)})
    ecosystems = sorted(
        {str(record.get("ecosystem") or "") for record in ghsa_records}
    )
    if (
        len(nvd_subjects) != 1
        or len(ghsa_subjects) != 2
        or len(ecosystems) != 1
        or ecosystems[0] not in TARGET_ECOSYSTEMS
    ):
        return None
    nvd_signature = cohort_util.range_signature(nvd_records)
    component_signatures = {
        component: cohort_util.range_signature(
            [record for record in ghsa_records if subject(record) == component]
        )
        for component in ghsa_subjects
    }
    signatures = [nvd_signature, *component_signatures.values()]
    if (
        not nvd_signature
        or len(nvd_signature) > MAX_SPANS_PER_CLAIM
        or any(
            not signature or len(signature) > MAX_SPANS_PER_CLAIM
            for signature in component_signatures.values()
        )
        or len(
            {
                canonical_signature(
                    [record for record in ghsa_records if subject(record) == component]
                )
                for component in ghsa_subjects
            }
        )
        < 2
        or not boundaries_parse(signatures)
    ):
        return None
    ecosystem = ecosystems[0]
    return {
        "schema_version": SCHEMA_VERSION,
        "sample_id": f"artifact_lineage_unseen_ecosystem_v1:{ecosystem.lower().replace('.', '').replace(' ', '_')}",
        "cve_id": row["cve_id"],
        "field": "affected_versions",
        "ecosystem": ecosystem,
        "nvd_subject": nvd_subjects[0],
        "ghsa_subjects": ghsa_subjects,
        "nvd_range_signature": nvd_signature,
        "ghsa_component_range_signatures": component_signatures,
        "nvd_value": nvd_records,
        "ghsa_value": ghsa_records,
        "reference_context": {
            "nvd_urls": reference_urls([row["nvd"]]),
            "ghsa_urls": reference_urls(row["ghsa"]),
            "ghsa_ids": sorted(
                str(advisory.get("source_id") or "")
                for advisory in row["ghsa"]
                if advisory.get("source_id")
            ),
        },
        "source_line_number": row["_input_line_number"],
        "selection_rank_sha256": hashlib.sha256(row["cve_id"].encode()).hexdigest(),
        "selection_uses_reviewer_labels": False,
        "selection_uses_non_human_consensus": False,
        "upstream_source_conditioned_on_non_human_consensus": False,
        "development_diagnostic_only": True,
        "post_unsealing": True,
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
    }


def build_cohort(rows: list[dict]) -> tuple[list[dict], dict[str, int]]:
    eligible = [candidate for row in rows if (candidate := eligible_row(row))]
    by_ecosystem: dict[str, list[dict]] = defaultdict(list)
    for row in eligible:
        by_ecosystem[row["ecosystem"]].append(row)
    eligible_counts = {
        ecosystem: len(by_ecosystem[ecosystem]) for ecosystem in TARGET_ECOSYSTEMS
    }
    selected = []
    for ecosystem in TARGET_ECOSYSTEMS:
        candidates = sorted(
            by_ecosystem[ecosystem],
            key=lambda row: (row["selection_rank_sha256"], row["cve_id"]),
        )
        if not candidates:
            raise ValueError(f"no eligible row for {ecosystem}")
        selected.append(candidates[0])
    selected.sort(key=lambda row: TARGET_ECOSYSTEMS.index(row["ecosystem"]))
    observed = {row["ecosystem"]: row["cve_id"] for row in selected}
    if observed != EXPECTED_CVES:
        raise ValueError(
            f"unseen-ecosystem cohort drift: expected {EXPECTED_CVES}, observed {observed}"
        )
    return selected, eligible_counts


def main() -> int:
    args = parse_args()
    source_path = resolve(args.source)
    output_dir = resolve(args.output_dir)
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite sealed cohort: {output_dir}")
    cohort, eligible_counts = build_cohort(read_jsonl(source_path))
    output_dir.mkdir(parents=True, exist_ok=False)
    cohort_path = output_dir / "cohort.jsonl"
    manifest_path = output_dir / "manifest.sealed.json"
    with cohort_path.open("w", encoding="utf-8") as handle:
        for row in cohort:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "artifact_lineage_unseen_ecosystem_cohort_manifest",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sealed": True,
        "source": {"path": str(source_path), "sha256": sha256(source_path)},
        "output": {"path": str(cohort_path), "sha256": sha256(cohort_path)},
        "selection": {
            "target_ecosystems": list(TARGET_ECOSYSTEMS),
            "one_nvd_subject": True,
            "exactly_two_ghsa_subjects": True,
            "single_ghsa_ecosystem": True,
            "component_range_signatures_differ": True,
            "maximum_spans_per_claim": MAX_SPANS_PER_CLAIM,
            "all_nonzero_boundaries_parseable": True,
            "rank": "minimum_sha256(cve_id)_per_ecosystem",
            "selection_uses_reviewer_labels": False,
            "selection_uses_non_human_consensus": False,
            "upstream_source_conditioned_on_non_human_consensus": False,
        },
        "eligible_counts": eligible_counts,
        "selected_count": len(cohort),
        "selected_cves": {row["ecosystem"]: row["cve_id"] for row in cohort},
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
    print(f"Selected {len(cohort)} rows from full aligned input without labels")
    print(f"Eligible counts: {eligible_counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
