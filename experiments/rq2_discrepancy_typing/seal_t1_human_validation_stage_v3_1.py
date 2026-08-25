#!/usr/bin/env python3
"""Seal two valid independent V3.1 returns for one phase and stage."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import build_t1_human_validation_packet_v3_1 as builder
import validate_t1_human_validation_return_v3_1 as return_validator


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet-dir", default=builder.DEFAULT_OUTPUT_DIR)
    parser.add_argument("--phase", choices=builder.PHASES, required=True)
    parser.add_argument("--stage", choices=builder.STAGES, required=True)
    parser.add_argument("--reviewer-a-return", required=True)
    parser.add_argument("--reviewer-b-return", required=True)
    parser.add_argument(
        "--prior-action-lock",
        help="Required for a reason-stage lock from the same phase.",
    )
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def raw_agreement(
    rows_a: list[dict[str, Any]],
    rows_b: list[dict[str, Any]],
    stage: str,
) -> tuple[int, int, float]:
    label_key = "action_label" if stage == "action" else "reason_label"
    by_id_b = {row["case_id"]: row for row in rows_b}
    agreements = sum(
        row["annotation"][label_key]
        == by_id_b[row["case_id"]]["annotation"][label_key]
        for row in rows_a
    )
    total = len(rows_a)
    return agreements, total, agreements / total if total else 0.0


def validate_prior_action_lock(path: Path, phase: str) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"missing prior action lock: {path}")
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid prior action lock JSON: {path}") from exc
    if (
        lock.get("schema_version") != "t1_v31_stage_lock_v1"
        or lock.get("protocol_id") != builder.PROTOCOL_ID
        or lock.get("phase") != phase
        or lock.get("stage") != "action"
        or lock.get("locked") is not True
    ):
        raise ValueError("prior action lock does not authorize this reason phase")
    return lock


def build_lock(
    packet_dir: Path,
    phase: str,
    stage: str,
    reviewer_a_path: Path,
    reviewer_b_path: Path,
    prior_action_lock_path: Path | None = None,
) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    receipts: dict[str, Any] = {}
    returns: dict[str, list[dict[str, Any]]] = {}
    for reviewer, path in (
        ("reviewer_a", reviewer_a_path),
        ("reviewer_b", reviewer_b_path),
    ):
        reviewer_errors, receipt, rows = return_validator.validate_return_file(
            packet_dir,
            reviewer,
            phase,
            stage,
            path,
            validate_packet_seal=(reviewer == "reviewer_a"),
        )
        errors.extend(reviewer_errors)
        receipts[reviewer] = receipt
        returns[reviewer] = rows
    prior_lock: dict[str, Any] | None = None
    if stage == "reason":
        if prior_action_lock_path is None:
            errors.append("reason-stage lock requires --prior-action-lock")
        else:
            try:
                prior_lock = validate_prior_action_lock(
                    prior_action_lock_path, phase
                )
            except ValueError as exc:
                errors.append(str(exc))
    elif prior_action_lock_path is not None:
        errors.append("action-stage lock must not receive --prior-action-lock")

    if errors:
        return errors, {
            "schema_version": "t1_v31_stage_lock_v1",
            "protocol_id": builder.PROTOCOL_ID,
            "phase": phase,
            "stage": stage,
            "locked": False,
            "errors": errors,
        }

    agreements, total, agreement = raw_agreement(
        returns["reviewer_a"],
        returns["reviewer_b"],
        stage,
    )
    lock = {
        "schema_version": "t1_v31_stage_lock_v1",
        "protocol_id": builder.PROTOCOL_ID,
        "phase": phase,
        "stage": stage,
        "locked": True,
        "reviewer_returns": {
            reviewer: {
                "path": receipt["return_file"],
                "sha256": receipt["return_file_sha256"],
                "rows": receipt["rows"],
                "validation_receipt": receipt,
            }
            for reviewer, receipt in receipts.items()
        },
        "inter_reviewer": {
            "agreements": agreements,
            "rows": total,
            "raw_agreement": agreement,
        },
        "prior_action_lock": (
            {
                "path": str(prior_action_lock_path),
                "reviewer_return_hashes": {
                    reviewer: value["sha256"]
                    for reviewer, value in prior_lock["reviewer_returns"].items()
                },
            }
            if prior_lock is not None
            else None
        ),
        "next_stage": {
            "reason_release_authorized_by_return_completeness": stage == "action",
            "author_distribution_approval_still_required": True,
        },
        "calibration_threshold": (
            {
                "threshold": 0.60,
                "met": agreement >= 0.60,
                "interpretation": (
                    "calibration-1 may still require calibration-2 after a "
                    "material guideline change; calibration-2 below threshold "
                    "terminates formal distribution"
                ),
            }
            if stage == "action" and phase.startswith("calibration_")
            else None
        ),
        "claim_ceiling": {
            "stage_complete": True,
            "inter_reviewer_agreement_descriptive": True,
            "human_gold_established": False,
            "formal_distribution_authorized": False,
        },
        "errors": [],
    }
    return [], lock


def main() -> int:
    args = parse_args()
    output_path = resolve(args.output)
    if output_path.exists():
        raise FileExistsError(f"refusing to overwrite stage lock: {output_path}")
    errors, lock = build_lock(
        resolve(args.packet_dir),
        args.phase,
        args.stage,
        resolve(args.reviewer_a_return),
        resolve(args.reviewer_b_return),
        resolve(args.prior_action_lock) if args.prior_action_lock else None,
    )
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 2
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(lock, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        f"PASS: locked {args.phase}/{args.stage}; "
        f"rows={lock['inter_reviewer']['rows']} "
        f"raw_agreement={lock['inter_reviewer']['raw_agreement']:.3f}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
