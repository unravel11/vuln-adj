#!/usr/bin/env python3
"""Validate and merge dual Codex reviews for the snapshot-external RQ2 cohort."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

from merge_rq2_typing_holdout_reviews import (  # noqa: E402
    cohen_kappa,
    is_strict_consensus,
    load_unique,
    sha256,
    validate_review,
    write_jsonl,
)
from verify_rq2_post_profile_cohort import validate as verify_cohort  # noqa: E402


DEFAULT_BASE = "data/annotations/holdout/rq2_post_profile_snapshot_v1"
DEFAULT_OUTPUT = "results/holdout/rq2_post_profile_snapshot_v1/review"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-dir", default=DEFAULT_BASE)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{line_number}") from exc


def audit_request_log(
    path: Path,
    *,
    pass_id: str,
    expected_samples: set[str],
    execution: dict,
    input_hash: str,
    prompt_hash: str,
    manifest_hash: str,
) -> dict:
    attempts: list[dict] = []
    succeeded: list[str] = []
    sessions = set()
    usage = Counter()
    request_events = success_events = response_errors = 0
    for event in iter_jsonl(path):
        if event.get("pass_id") != pass_id:
            raise ValueError(f"{path}: pass_id drift")
        if event.get("event_type") == "request":
            request_events += 1
            if event.get("input_sha256") != input_hash:
                raise ValueError(f"{path}: input hash drift")
            if event.get("prompt_sha256") != prompt_hash:
                raise ValueError(f"{path}: prompt hash drift")
            if event.get("binding_manifest_sha256") != manifest_hash:
                raise ValueError(f"{path}: manifest hash drift")
            if event.get("execution_backend") != execution["backend"]:
                raise ValueError(f"{path}: backend drift")
            if event.get("execution_backend_version") != execution["version"]:
                raise ValueError(f"{path}: backend version drift")
            if event.get("execution_backend_sha256") != execution["sha256"]:
                raise ValueError(f"{path}: backend hash drift")
            if event.get("model") != execution["model"] or event.get("schedule") != "input":
                raise ValueError(f"{path}: model or schedule drift")
            sample_ids = [item.get("sample_id") for item in event.get("items") or []]
            if not sample_ids or len(sample_ids) != len(set(sample_ids)):
                raise ValueError(f"{path}: invalid request batch")
            attempts.append({"sample_ids": sample_ids, "status": "pending"})
        elif event.get("event_type") == "response_success":
            success_events += 1
            sample_ids = event.get("sample_ids")
            matching = next(
                (
                    attempt
                    for attempt in reversed(attempts)
                    if attempt["status"] == "pending"
                    and attempt["sample_ids"] == sample_ids
                ),
                None,
            )
            if matching is None:
                raise ValueError(f"{path}: success without matching request")
            matching["status"] = "success"
            session = event.get("execution_session_id")
            if not str(session or "").strip():
                raise ValueError(f"{path}: success lacks execution session")
            sessions.add(session)
            event_usage = event.get("execution_usage") or {}
            for key in ("input_tokens", "cached_input_tokens", "output_tokens"):
                value = event_usage.get(key, 0)
                if not isinstance(value, int) or value < 0:
                    raise ValueError(f"{path}: invalid usage.{key}")
                usage[key] += value
            succeeded.extend(sample_ids)
        elif event.get("event_type") == "response_error":
            response_errors += 1
            sample_ids = event.get("sample_ids")
            matching = next(
                (
                    attempt
                    for attempt in reversed(attempts)
                    if attempt["status"] == "pending"
                    and attempt["sample_ids"] == sample_ids
                ),
                None,
            )
            if matching is None:
                raise ValueError(f"{path}: error without matching request")
            matching["status"] = "response_error"
        else:
            raise ValueError(f"{path}: unknown request-log event")
    if len(succeeded) != len(set(succeeded)) or set(succeeded) != expected_samples:
        raise ValueError(f"{path}: successful sample coverage drift")
    failed_attempts = [attempt for attempt in attempts if attempt["status"] != "success"]
    if any(not set(attempt["sample_ids"]).issubset(expected_samples) for attempt in failed_attempts):
        raise ValueError(f"{path}: failed attempt includes an unexpected sample")
    return {
        "request_events": request_events,
        "success_events": success_events,
        "failed_attempts": len(failed_attempts),
        "unanswered_validation_attempts": sum(
            attempt["status"] == "pending" for attempt in failed_attempts
        ),
        "response_error_attempts": response_errors,
        "successful_rows": len(succeeded),
        "execution_sessions": len(sessions),
        "usage": dict(sorted(usage.items())),
        "session_ids": sessions,
    }


def render_markdown(summary: dict) -> str:
    return "\n".join(
        [
            "# RQ2 Snapshot-External Dual-Codex Review",
            "",
            "> Prediction-sealed development diagnostic; labels are non-human expert candidates.",
            "",
            f"- Rows: `{summary['rows']}`",
            f"- Exact label agreement: `{summary['exact_label_agreement']}/{summary['rows']}` (`{summary['exact_label_agreement_rate']:.4f}`)",
            f"- Cohen's kappa: `{summary['cohen_kappa']}`",
            f"- Strict consensus: `{summary['strict_consensus_rows']}/{summary['rows']}` (`{summary['strict_consensus_coverage']:.4f}`)",
            "",
            "Strict consensus excludes uncertain labels, low confidence, and either reviewer's review request. It is not human gold.",
            "",
        ]
    )


def main() -> int:
    args = parse_args()
    base_dir = resolve(args.base_dir)
    output_dir = resolve(args.output_dir)
    manifest_path = base_dir / "manifest.sealed.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    verify_cohort(manifest)
    manifest_hash = sha256(manifest_path)
    source_path = Path(manifest["outputs"]["source_rows"]["path"])
    blind_a_path = Path(manifest["outputs"]["blind_worklist_a"]["path"])
    blind_b_path = Path(manifest["outputs"]["blind_worklist_b"]["path"])
    prompt_path = Path(manifest["inputs"]["prompt"]["path"])
    protocol = manifest["review_protocol"]
    execution = protocol["execution_contract"]
    reviewer_a_path = Path(protocol["reviewer_a_output"])
    reviewer_b_path = Path(protocol["reviewer_b_output"])
    request_a_path = Path(protocol["reviewer_a_request_log"])
    request_b_path = Path(protocol["reviewer_b_request_log"])
    for path in (reviewer_a_path, reviewer_b_path, request_a_path, request_b_path):
        if not path.is_file():
            raise FileNotFoundError(path)
        if path.stat().st_mtime_ns <= manifest["sealed_at_ns"]:
            raise ValueError(f"review artifact predates cohort seal: {path}")
    if reviewer_a_path == reviewer_b_path or sha256(reviewer_a_path) == sha256(reviewer_b_path):
        raise ValueError("reviewer outputs must be distinct")

    source = load_unique(source_path)
    blind_a = load_unique(blind_a_path)
    blind_b = load_unique(blind_b_path)
    review_a = load_unique(reviewer_a_path)
    review_b = load_unique(reviewer_b_path)
    sample_ids = list(source)
    if not all(set(rows) == set(sample_ids) for rows in (blind_a, blind_b, review_a, review_b)):
        raise ValueError("source/blind/reviewer sample sets differ")
    if list(blind_a) != sample_ids or list(blind_b) != list(reversed(sample_ids)):
        raise ValueError("sealed worklist order drift")

    log_a = audit_request_log(
        request_a_path,
        pass_id=protocol["reviewer_a_pass_id"],
        expected_samples=set(sample_ids),
        execution=execution,
        input_hash=sha256(blind_a_path),
        prompt_hash=sha256(prompt_path),
        manifest_hash=manifest_hash,
    )
    log_b = audit_request_log(
        request_b_path,
        pass_id=protocol["reviewer_b_pass_id"],
        expected_samples=set(sample_ids),
        execution=execution,
        input_hash=sha256(blind_b_path),
        prompt_hash=sha256(prompt_path),
        manifest_hash=manifest_hash,
    )
    if log_a["session_ids"] & log_b["session_ids"]:
        raise ValueError("review request logs share an execution session")

    merged = []
    labels_a = []
    labels_b = []
    for sample_id in sample_ids:
        left = validate_review(
            review_a[sample_id],
            blind_a[sample_id],
            expected_pass_id=protocol["reviewer_a_pass_id"],
            expected_input_path=blind_a_path,
            expected_prompt_path=prompt_path,
            expected_manifest_path=manifest_path,
            expected_manifest_sha256=manifest_hash,
            expected_execution=execution,
        )
        right = validate_review(
            review_b[sample_id],
            blind_b[sample_id],
            expected_pass_id=protocol["reviewer_b_pass_id"],
            expected_input_path=blind_b_path,
            expected_prompt_path=prompt_path,
            expected_manifest_path=manifest_path,
            expected_manifest_sha256=manifest_hash,
            expected_execution=execution,
        )
        if review_a[sample_id]["execution_session_id"] not in log_a["session_ids"]:
            raise ValueError(f"{sample_id}: reviewer A session absent from request log")
        if review_b[sample_id]["execution_session_id"] not in log_b["session_ids"]:
            raise ValueError(f"{sample_id}: reviewer B session absent from request log")
        strict = is_strict_consensus(left, right)
        labels_a.append(left["discrepancy_label"])
        labels_b.append(right["discrepancy_label"])
        merged.append(
            {
                "sample_id": sample_id,
                "cve_id": source[sample_id]["cve_id"],
                "field": source[sample_id]["field"],
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "strict_consensus": strict,
                "consensus_label": left["discrepancy_label"] if strict else None,
                "reviewer_a": left,
                "reviewer_b": right,
            }
        )

    strict_rows = [row for row in merged if row["strict_consensus"]]
    exact = sum(left == right for left, right in zip(labels_a, labels_b))
    per_field = {}
    for field in sorted({row["field"] for row in merged}):
        subset = [row for row in merged if row["field"] == field]
        per_field[field] = {
            "rows": len(subset),
            "exact_label_agreement": sum(
                row["reviewer_a"]["discrepancy_label"]
                == row["reviewer_b"]["discrepancy_label"]
                for row in subset
            ),
            "strict_consensus_rows": sum(row["strict_consensus"] for row in subset),
        }
    summary = {
        "artifact_type": "rq2_post_profile_snapshot_dual_codex_review",
        "selected_tier": "snapshot_external",
        "snapshot_external_is_time_confirmatory": False,
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "rows": len(merged),
        "unique_cves": len({row["cve_id"] for row in merged}),
        "reviewer_a_label_counts": dict(sorted(Counter(labels_a).items())),
        "reviewer_b_label_counts": dict(sorted(Counter(labels_b).items())),
        "exact_label_agreement": exact,
        "exact_label_agreement_rate": exact / len(merged),
        "cohen_kappa": cohen_kappa(labels_a, labels_b),
        "strict_consensus_rows": len(strict_rows),
        "strict_consensus_coverage": len(strict_rows) / len(merged),
        "strict_label_counts": dict(sorted(Counter(row["consensus_label"] for row in strict_rows).items())),
        "per_field": per_field,
        "request_log_audit": {
            "reviewer_a": {key: value for key, value in log_a.items() if key != "session_ids"},
            "reviewer_b": {key: value for key, value in log_b.items() if key != "session_ids"},
        },
        "source_manifest": {"path": str(manifest_path), "sha256": manifest_hash},
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    consensus_path = output_dir / "dual_review_consensus.jsonl"
    summary_path = output_dir / "dual_review_summary.json"
    markdown_path = output_dir / "dual_review_summary.md"
    merge_manifest_path = output_dir / "merge_manifest.json"
    write_jsonl(consensus_path, merged)
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(summary), encoding="utf-8")
    merge_manifest = {
        "artifact_type": "rq2_post_profile_snapshot_merge_manifest",
        "label_is_human": False,
        "inputs": {
            "sealed_manifest": {"path": str(manifest_path), "sha256": manifest_hash},
            "reviewer_a": {"path": str(reviewer_a_path), "sha256": sha256(reviewer_a_path)},
            "reviewer_b": {"path": str(reviewer_b_path), "sha256": sha256(reviewer_b_path)},
            "request_log_a": {"path": str(request_a_path), "sha256": sha256(request_a_path)},
            "request_log_b": {"path": str(request_b_path), "sha256": sha256(request_b_path)},
        },
        "outputs": {
            "consensus": {"path": str(consensus_path), "sha256": sha256(consensus_path)},
            "summary": {"path": str(summary_path), "sha256": sha256(summary_path)},
            "markdown": {"path": str(markdown_path), "sha256": sha256(markdown_path)},
        },
    }
    merge_manifest_path.write_text(
        json.dumps(merge_manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
