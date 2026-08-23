#!/usr/bin/env python3
"""Build baseline-blinded preparation packets for the JSS T1 human study."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROTOCOL_ID = "vuln-adj-jss-t1-human-validation-v2"
PACKET_SCHEMA_VERSION = "t1_human_review_packet_v1"
MANIFEST_SCHEMA_VERSION = "t1_packet_manifest_v1"

DEFAULT_FIELD_VIEW = (
    "data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl"
)
DEFAULT_GUIDELINE = "docs/annotation_guidelines/rq2_discrepancy_typing.md"
DEFAULT_PROTOCOL = (
    "experiments/rq2_discrepancy_typing/T1_HUMAN_VALIDATION_PROTOCOL.md"
)
DEFAULT_OUTPUT_DIR = "data/annotations/rq2/t1_human_validation_v2"

EXPECTED_FIELD_VIEW_SHA256 = (
    "c4bb405399bd0050c206b63ece95771c4f566a9a3968f123a16cf02a3b5cc3a2"
)
FIELDS = ("severity", "published", "references", "affected_versions", "cwe_ids")
PRIMARY_FIELDS = ("severity", "published", "references", "affected_versions")
SUPPLEMENTARY_FIELDS = ("cwe_ids",)
STATUSES = (
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
)

ROWS_PER_FIELD = 60
CALIBRATION_PER_FIELD = 10
EVALUATION_PER_FIELD = 50
SAMPLING_SEED = 20260823
SPLIT_SEED = 20260824
SIDE_MASK_SEED = 20260825
REVIEWER_A_ORDER_SEED = 20260826
REVIEWER_B_ORDER_SEED = 20260827

ANNOTATION_TEMPLATE = {
    "label": "",
    "rationale": "",
    "uncertainty_reason": "",
    "reviewer_notes": "",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build prepare-only, baseline-blinded calibration and evaluation "
            "packets for two real reviewers."
        )
    )
    parser.add_argument("--field-view", default=DEFAULT_FIELD_VIEW)
    parser.add_argument("--guideline", default=DEFAULT_GUIDELINE)
    parser.add_argument("--protocol", default=DEFAULT_PROTOCOL)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def relative_to_project(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path.resolve())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON at {path}:{line_number}: {exc}") from exc
    return rows


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def json_cell(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def write_packet_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fieldnames = [
        "packet_position",
        "case_id",
        "phase",
        "cve_id",
        "field",
        "left_value_json",
        "left_field_context_json",
        "left_package_names_json",
        "left_reference_urls_json",
        "left_reference_hosts_json",
        "right_value_json",
        "right_field_context_json",
        "right_package_names_json",
        "right_reference_urls_json",
        "right_reference_hosts_json",
        "label",
        "rationale",
        "uncertainty_reason",
        "reviewer_notes",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=fieldnames, lineterminator="\n"
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "packet_position": row["packet_position"],
                    "case_id": row["case_id"],
                    "phase": row["phase"],
                    "cve_id": row["cve_id"],
                    "field": row["field"],
                    "left_value_json": json_cell(row["left"]["value"]),
                    "left_field_context_json": json_cell(
                        row["left"]["field_context"]
                    ),
                    "left_package_names_json": json_cell(
                        row["left"]["package_names"]
                    ),
                    "left_reference_urls_json": json_cell(
                        row["left"]["reference_urls"]
                    ),
                    "left_reference_hosts_json": json_cell(
                        row["left"]["reference_hosts"]
                    ),
                    "right_value_json": json_cell(row["right"]["value"]),
                    "right_field_context_json": json_cell(
                        row["right"]["field_context"]
                    ),
                    "right_package_names_json": json_cell(
                        row["right"]["package_names"]
                    ),
                    "right_reference_urls_json": json_cell(
                        row["right"]["reference_urls"]
                    ),
                    "right_reference_hosts_json": json_cell(
                        row["right"]["reference_hosts"]
                    ),
                    **row["annotation"],
                }
            )


def expected_hash(path: Path, expected: str, label: str) -> None:
    actual = sha256_file(path)
    if actual != expected:
        raise ValueError(
            f"{label} hash mismatch: expected {expected}, observed {actual}: {path}"
        )


def current_source_projection(
    source_row: dict[str, Any], field: str, source_line_number: int
) -> dict[str, Any]:
    discrepancy = source_row["field_discrepancies"][field]
    unified_view = source_row["unified_view"]
    return {
        "sample_id": f"t1_v2:{field}:{source_line_number:05d}",
        "source_line_number": source_line_number,
        "field": field,
        "cve_id": source_row.get("cve_id"),
        "nvd_source_id": source_row.get("nvd_source_id"),
        "ghsa_source_id": source_row.get("ghsa_source_id"),
        "baseline_status": discrepancy.get("status"),
        "baseline_note": discrepancy.get("note"),
        "nvd_value": discrepancy.get("nvd_value"),
        "ghsa_value": discrepancy.get("ghsa_value"),
        "field_context": unified_view.get(field),
        "package_names": unified_view.get("package_names"),
        "reference_context": unified_view.get("references"),
    }


def validate_field_view(field_view_path: Path) -> list[dict[str, Any]]:
    expected_hash(
        field_view_path, EXPECTED_FIELD_VIEW_SHA256, "Frozen field-view input"
    )
    source_rows = load_jsonl(field_view_path)
    if len(source_rows) != 8066:
        raise ValueError(f"Expected 8066 field-view rows, observed {len(source_rows)}")
    for line_number, row in enumerate(source_rows, start=1):
        if not str(row.get("cve_id", "")).startswith("CVE-"):
            raise ValueError(f"Invalid CVE ID at field-view line {line_number}")
        for field in FIELDS:
            discrepancy = row.get("field_discrepancies", {}).get(field)
            if not isinstance(discrepancy, dict):
                raise ValueError(
                    f"Missing {field} discrepancy at field-view line {line_number}"
                )
            if discrepancy.get("status") not in STATUSES:
                raise ValueError(
                    f"Unexpected {field} status at field-view line {line_number}: "
                    f"{discrepancy.get('status')}"
                )
    return source_rows


def allocate_sample_targets(
    counts: dict[str, int], target: int
) -> dict[str, int]:
    active = [status for status in STATUSES if counts.get(status, 0) > 0]
    if not active:
        raise ValueError("Cannot sample a field with no active strata")
    allocation = {status: 0 for status in active}
    remaining = target
    while remaining:
        expandable = [
            status
            for status in active
            if allocation[status] < counts[status]
        ]
        if not expandable:
            raise ValueError(
                f"Sampling allocation stopped before target {target}: counts={counts}"
            )
        per_status = max(1, remaining // len(expandable))
        for status in expandable:
            take = min(
                per_status,
                counts[status] - allocation[status],
                remaining,
            )
            allocation[status] += take
            remaining -= take
            if remaining == 0:
                break
    return allocation


def sample_current_frame(
    source_rows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    grouped: dict[str, dict[str, list[dict[str, Any]]]] = {
        field: defaultdict(list) for field in FIELDS
    }
    for source_line_number, source_row in enumerate(source_rows, start=1):
        for field in FIELDS:
            projected = current_source_projection(
                source_row, field, source_line_number
            )
            grouped[field][projected["baseline_status"]].append(projected)

    rng = random.Random(SAMPLING_SEED)
    sampled_rows: list[dict[str, Any]] = []
    sampling_strata: list[dict[str, Any]] = []
    for field in FIELDS:
        counts = {
            status: len(grouped[field].get(status, [])) for status in STATUSES
        }
        targets = allocate_sample_targets(counts, ROWS_PER_FIELD)
        for status in STATUSES:
            candidates = sorted(
                grouped[field].get(status, []),
                key=lambda row: row["source_line_number"],
            )
            selected = rng.sample(candidates, targets.get(status, 0))
            sampled_rows.extend(selected)
            if candidates:
                sampling_strata.append(
                    {
                        "field": field,
                        "baseline_status": status,
                        "population_count": len(candidates),
                        "sample_count": len(selected),
                    }
                )

    if len(sampled_rows) != 300:
        raise ValueError(
            f"Expected 300 sampled rows from current frame, observed {len(sampled_rows)}"
        )
    sample_ids = [row["sample_id"] for row in sampled_rows]
    if len(set(sample_ids)) != len(sample_ids):
        raise ValueError("V2 sampled case IDs are not unique")
    field_counts = Counter(row["field"] for row in sampled_rows)
    if dict(field_counts) != {field: ROWS_PER_FIELD for field in FIELDS}:
        raise ValueError(f"Unexpected V2 sampled field counts: {dict(field_counts)}")
    return sampled_rows, sampling_strata


def allocate_calibration_targets(
    counts: dict[str, int], target: int
) -> dict[str, int]:
    active = [status for status in STATUSES if counts.get(status, 0) > 0]
    caps = {status: max(0, counts[status] - 1) for status in active}
    if sum(caps.values()) < target:
        raise ValueError(
            f"Cannot allocate {target} calibration rows while retaining one "
            f"evaluation row in every active stratum: counts={counts}"
        )

    allocation = {status: 0 for status in active}
    remaining = target
    while remaining:
        expandable = [
            status for status in active if allocation[status] < caps[status]
        ]
        if not expandable:
            raise ValueError("Calibration allocation stopped before reaching target")
        per_status = max(1, remaining // len(expandable))
        for status in expandable:
            take = min(
                per_status,
                caps[status] - allocation[status],
                remaining,
            )
            allocation[status] += take
            remaining -= take
            if remaining == 0:
                break
    return allocation


def split_rows(
    sampled_rows: list[dict[str, Any]],
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    grouped: dict[str, dict[str, list[dict[str, Any]]]] = {
        field: defaultdict(list) for field in FIELDS
    }
    for row in sampled_rows:
        grouped[row["field"]][row["baseline_status"]].append(row)

    rng = random.Random(SPLIT_SEED)
    phase_by_sample_id: dict[str, str] = {}
    strata: list[dict[str, Any]] = []
    for field in FIELDS:
        counts = {
            status: len(grouped[field].get(status, [])) for status in STATUSES
        }
        targets = allocate_calibration_targets(counts, CALIBRATION_PER_FIELD)
        calibration_ids: set[str] = set()
        for status in STATUSES:
            candidates = sorted(
                grouped[field].get(status, []), key=lambda row: row["sample_id"]
            )
            selected = rng.sample(candidates, targets.get(status, 0))
            calibration_ids.update(str(row["sample_id"]) for row in selected)

        for status in STATUSES:
            seed_count = counts[status]
            if not seed_count:
                continue
            calibration_count = sum(
                1
                for row in grouped[field][status]
                if row["sample_id"] in calibration_ids
            )
            evaluation_count = seed_count - calibration_count
            if evaluation_count <= 0:
                raise ValueError(
                    f"No evaluation row remains for {field}/{status}"
                )
            strata.append(
                {
                    "field": field,
                    "baseline_status": status,
                    "seed_count": seed_count,
                    "calibration_count": calibration_count,
                    "evaluation_count": evaluation_count,
                }
            )

        for status_rows in grouped[field].values():
            for row in status_rows:
                phase_by_sample_id[row["sample_id"]] = (
                    "calibration"
                    if row["sample_id"] in calibration_ids
                    else "evaluation"
                )

    phase_counts = Counter(phase_by_sample_id.values())
    if dict(phase_counts) != {"calibration": 50, "evaluation": 250}:
        raise ValueError(f"Unexpected phase counts: {dict(phase_counts)}")
    return phase_by_sample_id, strata


def side_context(row: dict[str, Any], source: str) -> dict[str, Any]:
    field_context = row.get("field_context")
    if isinstance(field_context, dict) and source in field_context:
        field_context = field_context[source]
    elif isinstance(field_context, dict):
        prefixed_keys = [
            key
            for key in field_context
            if str(key).startswith("nvd_") or str(key).startswith("ghsa_")
        ]
        if prefixed_keys:
            neutral_context = {
                str(key)[len(source) + 1 :]: value
                for key, value in field_context.items()
                if str(key).startswith(f"{source}_")
            }
            neutral_context.update(
                {
                    key: value
                    for key, value in field_context.items()
                    if not str(key).startswith("nvd_")
                    and not str(key).startswith("ghsa_")
                }
            )
            field_context = neutral_context

    package_names = row.get("package_names") or {}
    if not isinstance(package_names, dict):
        raise ValueError(f"Invalid package_names for {row['sample_id']}")
    references = row.get("reference_context") or {}
    if not isinstance(references, dict):
        raise ValueError(f"Invalid reference_context for {row['sample_id']}")

    return {
        "value": row[f"{source}_value"],
        "field_context": field_context,
        "package_names": package_names.get(source, []),
        "reference_urls": references.get(f"{source}_urls", []),
        "reference_hosts": references.get(f"{source}_hosts", []),
    }


def opaque_case_id(sample_id: str, phase: str) -> str:
    digest = hashlib.sha256(
        f"{PROTOCOL_ID}|{phase}|{sample_id}".encode("utf-8")
    ).hexdigest()[:12]
    prefix = "cal" if phase == "calibration" else "eval"
    return f"t1-{prefix}-{digest}"


def build_cases(
    sampled_rows: list[dict[str, Any]], phase_by_sample_id: dict[str, str]
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    side_rng = random.Random(SIDE_MASK_SEED)
    cases_by_phase: dict[str, list[dict[str, Any]]] = {
        "calibration": [],
        "evaluation": [],
    }
    mapping: list[dict[str, Any]] = []

    for row in sorted(sampled_rows, key=lambda value: value["sample_id"]):
        phase = phase_by_sample_id[row["sample_id"]]
        left_source = "nvd" if side_rng.randrange(2) == 0 else "ghsa"
        right_source = "ghsa" if left_source == "nvd" else "nvd"
        case_id = opaque_case_id(row["sample_id"], phase)
        case = {
            "schema_version": PACKET_SCHEMA_VERSION,
            "protocol_id": PROTOCOL_ID,
            "phase": phase,
            "packet_position": 0,
            "case_id": case_id,
            "cve_id": row["cve_id"],
            "field": row["field"],
            "left": side_context(row, left_source),
            "right": side_context(row, right_source),
            "annotation": dict(ANNOTATION_TEMPLATE),
        }
        cases_by_phase[phase].append(case)
        mapping.append(
            {
                "case_id": case_id,
                "source_sample_id": row["sample_id"],
                "source_line_number": row["source_line_number"],
                "phase": phase,
                "cve_id": row["cve_id"],
                "field": row["field"],
                "baseline_status": row["baseline_status"],
                "baseline_note": row["baseline_note"],
                "left_source": left_source,
                "right_source": right_source,
                "reviewer_positions": {},
            }
        )

    return cases_by_phase, mapping


def ordered_packets(
    cases_by_phase: dict[str, list[dict[str, Any]]]
) -> dict[str, dict[str, list[dict[str, Any]]]]:
    packets: dict[str, dict[str, list[dict[str, Any]]]] = {
        "reviewer_a": {},
        "reviewer_b": {},
    }
    for reviewer, seed in (
        ("reviewer_a", REVIEWER_A_ORDER_SEED),
        ("reviewer_b", REVIEWER_B_ORDER_SEED),
    ):
        rng = random.Random(seed)
        for phase in ("calibration", "evaluation"):
            rows = [json.loads(json.dumps(row)) for row in cases_by_phase[phase]]
            rng.shuffle(rows)
            for position, row in enumerate(rows, start=1):
                row["packet_position"] = position
            packets[reviewer][phase] = rows
    return packets


def mapping_with_positions(
    mapping: list[dict[str, Any]],
    packets: dict[str, dict[str, list[dict[str, Any]]]],
) -> list[dict[str, Any]]:
    positions = {
        reviewer: {
            row["case_id"]: row["packet_position"]
            for phase_rows in phase_packets.values()
            for row in phase_rows
        }
        for reviewer, phase_packets in packets.items()
    }
    output = []
    for row in mapping:
        copied = dict(row)
        copied["reviewer_positions"] = {
            reviewer: positions[reviewer][row["case_id"]]
            for reviewer in ("reviewer_a", "reviewer_b")
        }
        output.append(copied)
    return sorted(output, key=lambda row: row["case_id"])


def role_record_text() -> str:
    return """# T1 Human Role and Independence Record

Status: INCOMPLETE_NOT_FOR_DISTRIBUTION

Complete and sign this record before calibration packets are distributed.

## Reviewer A

- Real name:
- Reviewer ID:
- Relevant expertise:
- Employer or affiliation:
- Conflicts of interest:
- Compensation:
- Independence statement signed:
- Date:

## Reviewer B

- Real name:
- Reviewer ID:
- Relevant expertise:
- Employer or affiliation:
- Conflicts of interest:
- Compensation:
- Independence statement signed:
- Date:

## Resolving author

- Real name:
- Author ID:
- Conflict statement:
- Baseline-blinding commitment signed:
- Date:

## Ethics and recruitment

- Institutional determination required:
- Determination identifier or rationale:
- Recruitment method:
- Consent or information sheet location:

## Author signoff

- I confirm that reviewers A and B are different real people:
- I confirm that neither reviewer received baseline, AI, Codex, or prior-review labels:
- I confirm that packet hashes match the manifest:
- Author name and signature:
- Date:
"""


def packet_readme_text() -> str:
    return """# T1 Human Validation Packet

Status: PREPARATION_ONLY_NOT_FOR_DISTRIBUTION

This directory contains blank, baseline-blinded packets for the JSS T1
protocol. It contains no real-human labels and is not human gold.

Distribution is blocked until:

1. the calibration guideline is versioned and author-approved;
2. the human role and independence record is complete;
3. a separate readiness check changes distribution_allowed only through a
   reviewed manifest revision.

Only reviewer-specific JSONL or CSV files may be distributed. The internal
sealed mapping contains baseline labels and source-side identities and must not
be shared with reviewers.
"""


def add_population_counts(
    strata: list[dict[str, Any]], sampling_strata: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    sampling_lookup = {
        (row["field"], row["baseline_status"]): row for row in sampling_strata
    }
    output = []
    for row in strata:
        key = (row["field"], row["baseline_status"])
        sampling = sampling_lookup[key]
        if int(sampling["sample_count"]) != int(row["seed_count"]):
            raise ValueError(
                f"Sampling/split count mismatch for {key}: "
                f"{sampling['sample_count']} != {row['seed_count']}"
            )
        population_count = int(sampling["population_count"])
        evaluation_count = int(row["evaluation_count"])
        output.append(
            {
                **row,
                "population_count": population_count,
                "evaluation_weight": population_count / evaluation_count,
            }
        )
    return output


def build_packet(
    field_view_path: Path,
    guideline_path: Path,
    protocol_path: Path,
    output_dir: Path,
) -> dict[str, Any]:
    required_paths = (
        field_view_path,
        guideline_path,
        protocol_path,
        Path(__file__).resolve(),
    )
    for path in required_paths:
        if not path.is_file():
            raise FileNotFoundError(path)
    if output_dir.exists():
        raise FileExistsError(
            f"Refusing to overwrite existing T1 packet directory: {output_dir}"
        )

    source_rows = validate_field_view(field_view_path)
    sampled_rows, sampling_strata = sample_current_frame(source_rows)
    phase_by_sample_id, strata = split_rows(sampled_rows)
    cases_by_phase, mapping = build_cases(sampled_rows, phase_by_sample_id)
    packets = ordered_packets(cases_by_phase)
    mapping = mapping_with_positions(mapping, packets)
    strata = add_population_counts(strata, sampling_strata)

    (output_dir / "internal").mkdir(parents=True)
    for reviewer in ("reviewer_a", "reviewer_b"):
        (output_dir / reviewer).mkdir()
        for phase in ("calibration", "evaluation"):
            rows = packets[reviewer][phase]
            write_jsonl(output_dir / reviewer / f"{phase}_packet.jsonl", rows)
            write_packet_csv(output_dir / reviewer / f"{phase}_packet.csv", rows)

    write_jsonl(
        output_dir / "internal" / "frozen_sampling_frame.jsonl",
        sorted(sampled_rows, key=lambda row: row["sample_id"]),
    )
    write_jsonl(output_dir / "internal" / "sealed_case_mapping.jsonl", mapping)
    (output_dir / "ROLE_AND_INDEPENDENCE_RECORD.md").write_text(
        role_record_text(), encoding="utf-8"
    )
    (output_dir / "README.md").write_text(packet_readme_text(), encoding="utf-8")

    generated_files = sorted(
        path
        for path in output_dir.rglob("*")
        if path.is_file() and path.name != "manifest.json"
    )
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "protocol_id": PROTOCOL_ID,
        "status": "PREPARATION_ONLY_NOT_FOR_DISTRIBUTION",
        "distribution_allowed": False,
        "distribution_blockers": [
            "Calibration guideline is still a draft and lacks author approval.",
            "Human role and independence record is incomplete.",
            "No real-human annotation has started.",
        ],
        "freeze_date": "2026-08-23",
        "input_files": {
            relative_to_project(path): sha256_file(path)
            for path in required_paths
        },
        "expected_input_hashes": {
            relative_to_project(field_view_path): EXPECTED_FIELD_VIEW_SHA256,
        },
        "seeds": {
            "sampling": SAMPLING_SEED,
            "split": SPLIT_SEED,
            "side_mask": SIDE_MASK_SEED,
            "reviewer_a_order": REVIEWER_A_ORDER_SEED,
            "reviewer_b_order": REVIEWER_B_ORDER_SEED,
        },
        "sampling_rule": (
            "60 rows per field, equalized across current non-empty deterministic "
            "baseline strata, sampled directly from the frozen field view"
        ),
        "counts": {
            "total": 300,
            "calibration": 50,
            "evaluation": 250,
            "per_field_total": ROWS_PER_FIELD,
            "per_field_calibration": CALIBRATION_PER_FIELD,
            "per_field_evaluation": EVALUATION_PER_FIELD,
        },
        "primary_fields": list(PRIMARY_FIELDS),
        "supplementary_fields": list(SUPPLEMENTARY_FIELDS),
        "strata": strata,
        "reviewer_packet_files": {
            reviewer: {
                phase: {
                    "jsonl": f"{reviewer}/{phase}_packet.jsonl",
                    "csv": f"{reviewer}/{phase}_packet.csv",
                }
                for phase in ("calibration", "evaluation")
            }
            for reviewer in ("reviewer_a", "reviewer_b")
        },
        "internal_sampling_frame": "internal/frozen_sampling_frame.jsonl",
        "internal_mapping": "internal/sealed_case_mapping.jsonl",
        "output_sha256": {
            str(path.relative_to(output_dir)): sha256_file(path)
            for path in generated_files
        },
        "cautions": [
            "These are blank preparation packets, not human labels or human gold.",
            "Reviewer files hide baseline labels and explicit NVD/GHSA side names.",
            "URLs may reveal source identity; source blinding is partial.",
            "The internal mapping must not be distributed to reviewers.",
        ],
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def main() -> int:
    args = parse_args()
    manifest = build_packet(
        field_view_path=resolve_path(args.field_view),
        guideline_path=resolve_path(args.guideline),
        protocol_path=resolve_path(args.protocol),
        output_dir=resolve_path(args.output_dir),
    )
    print(
        "Built T1 prepare-only packets: "
        f"calibration={manifest['counts']['calibration']} "
        f"evaluation={manifest['counts']['evaluation']} "
        "distribution_allowed=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
