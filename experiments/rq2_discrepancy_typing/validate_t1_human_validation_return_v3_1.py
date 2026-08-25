#!/usr/bin/env python3
"""Validate one completed V3.1 human return against its sealed blank packet."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

import build_t1_human_validation_packet_v3_1 as builder
import validate_t1_human_validation_packet_v3_1 as packet_validator
from analyze_t1_routing_precheck import ACTIONS


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ALLOWED_REASONS = set(builder.REASONS)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet-dir", default=builder.DEFAULT_OUTPUT_DIR)
    parser.add_argument("--reviewer", choices=builder.REVIEWERS, required=True)
    parser.add_argument("--phase", choices=builder.PHASES, required=True)
    parser.add_argument("--stage", choices=builder.STAGES, required=True)
    parser.add_argument("--return-file", required=True)
    parser.add_argument(
        "--receipt",
        help="Optional new JSON path for a validation receipt; never overwrites.",
    )
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def load_csv_return(path: Path, stage: str) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != packet_validator.expected_csv_fields(stage):
            raise ValueError("return CSV columns do not equal the frozen allowlist")
        csv_rows = list(reader)
    output: list[dict[str, Any]] = []
    annotation_keys = (
        builder.ACTION_ANNOTATION if stage == "action" else builder.REASON_ANNOTATION
    )
    for line_number, row in enumerate(csv_rows, start=2):
        try:
            output.append(
                {
                    "schema_version": builder.PACKET_SCHEMA_VERSION,
                    "protocol_id": builder.PROTOCOL_ID,
                    "phase": row["phase"],
                    "stage": row["stage"],
                    "packet_position": int(row["packet_position"]),
                    "case_id": row["case_id"],
                    "cve_id": row["cve_id"],
                    "field": row["field"],
                    "left": {
                        "value": json.loads(row["left_value_json"]),
                        "field_context": json.loads(
                            row["left_field_context_json"]
                        ),
                        "package_names": json.loads(
                            row["left_package_names_json"]
                        ),
                        "reference_urls": json.loads(
                            row["left_reference_urls_json"]
                        ),
                        "reference_hosts": json.loads(
                            row["left_reference_hosts_json"]
                        ),
                    },
                    "right": {
                        "value": json.loads(row["right_value_json"]),
                        "field_context": json.loads(
                            row["right_field_context_json"]
                        ),
                        "package_names": json.loads(
                            row["right_package_names_json"]
                        ),
                        "reference_urls": json.loads(
                            row["right_reference_urls_json"]
                        ),
                        "reference_hosts": json.loads(
                            row["right_reference_hosts_json"]
                        ),
                    },
                    "annotation": {key: row[key] for key in annotation_keys},
                }
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid return CSV row at {path}:{line_number}") from exc
    return output


def load_return(path: Path, stage: str) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".jsonl":
        return packet_validator.load_jsonl(path)
    if path.suffix.lower() == ".csv":
        return load_csv_return(path, stage)
    raise ValueError("return file must be .jsonl or .csv")


def immutable_payload(row: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in row.items() if key != "annotation"}


def validate_annotation(
    annotation: Any,
    stage: str,
    label: str,
    errors: list[str],
) -> None:
    expected = (
        set(builder.ACTION_ANNOTATION)
        if stage == "action"
        else set(builder.REASON_ANNOTATION)
    )
    if not isinstance(annotation, dict) or set(annotation) != expected:
        errors.append(f"{label}: annotation keys do not equal stage allowlist")
        return
    if any(not isinstance(value, str) for value in annotation.values()):
        errors.append(f"{label}: all annotation values must be strings")
        return
    label_key = "action_label" if stage == "action" else "reason_label"
    rationale_key = (
        "action_rationale" if stage == "action" else "reason_rationale"
    )
    allowed = set(ACTIONS) if stage == "action" else ALLOWED_REASONS
    if annotation[label_key] not in allowed:
        errors.append(f"{label}: invalid {label_key}")
    if not annotation[rationale_key].strip():
        errors.append(f"{label}: rationale is required")


def validate_return_rows(
    blank_rows: list[dict[str, Any]],
    return_rows: list[dict[str, Any]],
    reviewer: str,
    phase: str,
    stage: str,
) -> list[str]:
    errors: list[str] = []
    if len(return_rows) != len(blank_rows):
        errors.append(
            f"{reviewer}/{phase}/{stage}: expected {len(blank_rows)} rows, "
            f"observed {len(return_rows)}"
        )
        return errors
    blank_ids = [row["case_id"] for row in blank_rows]
    return_ids = [row.get("case_id") for row in return_rows]
    if len(set(return_ids)) != len(return_ids):
        errors.append(f"{reviewer}/{phase}/{stage}: duplicate case IDs")
    if return_ids != blank_ids:
        errors.append(
            f"{reviewer}/{phase}/{stage}: case set or order differs from blank packet"
        )
        return errors
    for position, (blank, returned) in enumerate(
        zip(blank_rows, return_rows), start=1
    ):
        label = f"{reviewer}/{phase}/{stage}:{position}"
        if set(returned) != builder.TOP_LEVEL_KEYS:
            errors.append(f"{label}: top-level keys do not equal allowlist")
            continue
        if immutable_payload(returned) != immutable_payload(blank):
            errors.append(f"{label}: sealed packet content was modified")
        validate_annotation(returned.get("annotation"), stage, label, errors)
        banned = packet_validator.find_banned_keys(returned)
        if banned:
            errors.append(f"{label}: returned packet exposes banned keys {banned[:5]}")
    return errors


def validate_return_file(
    packet_dir: Path,
    reviewer: str,
    phase: str,
    stage: str,
    return_path: Path,
    *,
    validate_packet_seal: bool = True,
) -> tuple[list[str], dict[str, Any], list[dict[str, Any]]]:
    errors: list[str] = []
    if validate_packet_seal:
        errors.extend(packet_validator.validate_packet_dir(packet_dir))
    blank_path = packet_dir / reviewer / f"{phase}_{stage}_packet.jsonl"
    if not blank_path.is_file():
        return [f"missing blank packet: {blank_path}"], {}, []
    if not return_path.is_file():
        return [f"missing return file: {return_path}"], {}, []
    try:
        blank_rows = packet_validator.load_jsonl(blank_path)
        return_rows = load_return(return_path, stage)
    except (OSError, ValueError) as exc:
        return [str(exc)], {}, []
    errors.extend(
        validate_return_rows(
            blank_rows,
            return_rows,
            reviewer,
            phase,
            stage,
        )
    )
    label_key = "action_label" if stage == "action" else "reason_label"
    label_counts = Counter(
        row.get("annotation", {}).get(label_key) for row in return_rows
    )
    receipt = {
        "schema_version": "t1_v31_return_validation_receipt_v1",
        "protocol_id": builder.PROTOCOL_ID,
        "valid": not errors,
        "reviewer": reviewer,
        "phase": phase,
        "stage": stage,
        "rows": len(return_rows),
        "blank_packet": str(blank_path),
        "blank_packet_sha256": packet_validator.sha256_file(blank_path),
        "return_file": str(return_path),
        "return_file_sha256": packet_validator.sha256_file(return_path),
        "label_counts": dict(sorted(label_counts.items(), key=lambda item: str(item[0]))),
        "errors": errors,
        "claim_ceiling": {
            "independence_proven_by_file_validation": False,
            "human_gold_established": False,
            "policy_result_established": False,
        },
    }
    return errors, receipt, return_rows


def main() -> int:
    args = parse_args()
    packet_dir = resolve(args.packet_dir)
    return_path = resolve(args.return_file)
    errors, receipt, _ = validate_return_file(
        packet_dir,
        args.reviewer,
        args.phase,
        args.stage,
        return_path,
    )
    if args.receipt:
        receipt_path = resolve(args.receipt)
        if receipt_path.exists():
            raise FileExistsError(f"refusing to overwrite receipt: {receipt_path}")
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(
            json.dumps(receipt, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 2
    print(
        f"PASS: {args.reviewer}/{args.phase}/{args.stage} return is complete; "
        f"rows={receipt['rows']} sha256={receipt['return_file_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
