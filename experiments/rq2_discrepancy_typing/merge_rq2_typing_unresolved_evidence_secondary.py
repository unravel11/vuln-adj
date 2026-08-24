#!/usr/bin/env python3
"""Merge evidence-enhanced D/E reviews for the 37 unresolved RQ2 rows."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

import build_rq2_typing_unresolved_evidence_secondary as builder
import evaluate_rq2_typing_holdout as evaluation
import merge_rq2_typing_holdout_reviews as dual


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASE_DIR = builder.DEFAULT_OUTPUT_DIR
DEFAULT_OUTPUT_DIR = (
    "results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1"
)
EXPECTED_PARENT_CANDIDATES = 1213
EXPECTED_TOTAL_ROWS = 1250


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-dir", default=DEFAULT_BASE_DIR)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def write_json(path: Path, value: dict) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def verified_record(record: dict, name: str) -> Path:
    path = Path(record["path"])
    if not path.is_file() or dual.sha256(path) != record.get("sha256"):
        raise ValueError(f"hash or path mismatch for {name}: {path}")
    return path


def successful_urls(blind: dict) -> set[str]:
    return {
        record["url"]
        for record in (blind.get("evidence_context") or {}).get("records", [])
        if record.get("fetch_status") == "ok"
        and str(record.get("text_snippet") or "").strip()
    }


def citation_passed(annotation: dict, blind: dict, required: bool) -> bool:
    if not required:
        return True
    return bool(set(annotation["evidence_urls"]) & successful_urls(blind))


def validate_request_log(
    path: Path,
    worklist: dict[str, dict],
    manifest: dict,
    pass_id: str,
    reviewer_sessions: set[str],
) -> dict:
    events = list(dual.iter_jsonl(path))
    if not events or len(events) % 2:
        raise ValueError(f"{path}: request log must contain request/success pairs")
    requested_ids = []
    success_sessions = set()
    batch_sizes = []
    manifest_path = Path(manifest["outputs"]["blind_worklist_d"]["path"]).parents[1] / "manifest.sealed.json"
    for index in range(0, len(events), 2):
        request, response = events[index : index + 2]
        if request.get("event_type") != "request" or response.get("event_type") != "response_success":
            raise ValueError(f"{path}: non-success request-log pair")
        items = request.get("items")
        if not isinstance(items, list) or not items:
            raise ValueError(f"{path}: request without items")
        sample_ids = [item.get("sample_id") for item in items]
        if response.get("sample_ids") != sample_ids:
            raise ValueError(f"{path}: response sample order mismatch")
        if request.get("pass_id") != pass_id:
            raise ValueError(f"{path}: pass ID drift")
        if request.get("input_sha256") != dual.sha256(Path(next(iter(worklist.values()))["_input_path"])):
            raise ValueError(f"{path}: request input hash drift")
        if request.get("binding_manifest_sha256") != dual.sha256(manifest_path):
            raise ValueError(f"{path}: binding manifest hash drift")
        requested_ids.extend(sample_ids)
        batch_sizes.append(len(sample_ids))
        success_sessions.add(response.get("execution_session_id"))
    if requested_ids != list(worklist):
        raise ValueError(f"{path}: request schedule differs from sealed input order")
    if success_sessions != reviewer_sessions or None in success_sessions:
        raise ValueError(f"{path}: request sessions differ from accepted output")
    return {
        "event_count": len(events),
        "request_count": len(events) // 2,
        "response_success_count": len(events) // 2,
        "response_error_count": 0,
        "batch_sizes": batch_sizes,
        "session_count": len(success_sessions),
    }


def load_worklist(path: Path) -> dict[str, dict]:
    rows = dual.load_unique(path)
    for row in rows.values():
        row["_input_path"] = str(path)
    return rows


def build_gate(evidence_rate: float, strict_rows: int, combined_rows: int) -> dict:
    checks = {
        "minimum_evidence_availability": (
            evidence_rate >= builder.MIN_EVIDENCE_AVAILABILITY
        ),
        "minimum_secondary_strict_resolution": (
            strict_rows / builder.EXPECTED_ROWS
            >= builder.MIN_SECONDARY_STRICT_RESOLUTION
        ),
        "minimum_combined_candidate_coverage": (
            combined_rows / EXPECTED_TOTAL_ROWS
            >= builder.MIN_COMBINED_CANDIDATE_COVERAGE
        ),
        "non_human_boundary_preserved": True,
    }
    passed = all(checks.values())
    return {
        "status": (
            "pass_non_human_evidence_secondary_development_only"
            if passed
            else "no_go_non_human_evidence_secondary"
        ),
        "passed": passed,
        "checks": checks,
        "failed_checks": [name for name, value in checks.items() if not value],
        "thresholds": {
            "minimum_evidence_availability": builder.MIN_EVIDENCE_AVAILABILITY,
            "minimum_secondary_strict_resolution": builder.MIN_SECONDARY_STRICT_RESOLUTION,
            "minimum_combined_candidate_coverage": builder.MIN_COMBINED_CANDIDATE_COVERAGE,
        },
        "scope": "post_unsealing_same_model_non_human_development_only",
        "human_gold_claim_allowed": False,
        "accuracy_claim_allowed": False,
        "production_switch_allowed": False,
    }


def candidate_metrics(rows: list[dict], predictions: dict[str, dict]) -> dict:
    resolved = [row for row in rows if row["candidate_label"] is not None]
    records = [
        {
            "gold": row["candidate_label"],
            "current": predictions[row["sample_id"]]["current"],
        }
        for row in resolved
    ]
    correct = sum(row["gold"] == row["current"] for row in records)
    per_field = {}
    for field in sorted({row["field"] for row in rows}):
        all_field = [row for row in rows if row["field"] == field]
        field_resolved = [row for row in all_field if row["candidate_label"] is not None]
        field_correct = sum(
            predictions[row["sample_id"]]["current"] == row["candidate_label"]
            for row in field_resolved
        )
        per_field[field] = {
            "rows": len(all_field),
            "candidate_rows": len(field_resolved),
            "candidate_coverage": len(field_resolved) / len(all_field),
            "agreement_count": field_correct,
            "agreement_on_candidate_rows": (
                field_correct / len(field_resolved) if field_resolved else 0.0
            ),
            "full_cohort_lower_bound_agreement": field_correct / len(all_field),
        }
    return {
        "rows": len(rows),
        "candidate_rows": len(resolved),
        "candidate_coverage": len(resolved) / len(rows),
        "agreement_count": correct,
        "agreement_on_candidate_rows": correct / len(resolved),
        "macro_f1_on_candidate_rows": evaluation.macro_f1(records, "current"),
        "full_cohort_lower_bound_agreement": correct / len(rows),
        "per_field": per_field,
        "metric_boundary": (
            "agreement with a post-selected same-model-family non-human candidate; "
            "not human-gold accuracy"
        ),
    }


def render_markdown(summary: dict, metrics: dict) -> str:
    return "\n".join(
        [
            "# RQ2 Unresolved Evidence Secondary v1",
            "",
            "> Post-unsealing, same-model-family, non-human evidence audit.",
            "",
            f"- Selected unresolved rows: `{summary['selected_rows']}`",
            f"- Rows with successful evidence: `{summary['rows_with_successful_evidence']}/{summary['selected_rows']}`",
            f"- Evidence-qualified D/E strict rows: `{summary['secondary_strict_rows']}/{summary['selected_rows']}`",
            f"- Combined candidate coverage: `{summary['combined_candidate_rows']}/{summary['total_rows']}` (`{summary['combined_candidate_coverage']:.4f}`)",
            f"- Gate: `{summary['advancement_gate']['status']}`",
            f"- Baseline agreement on combined candidate rows: `{metrics['agreement_count']}/{metrics['candidate_rows']}` (`{metrics['agreement_on_candidate_rows']:.4f}`)",
            "- `label_is_human=false`",
            "",
            "No output is human gold or confirmatory accuracy evidence.",
            "",
        ]
    )


def main() -> int:
    args = parse_args()
    base_dir = resolve(args.base_dir)
    output_dir = resolve(args.output_dir)
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite result: {output_dir}")
    manifest_path = base_dir / "manifest.sealed.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("artifact_type") != "rq2_typing_unresolved_evidence_secondary_manifest":
        raise ValueError("unexpected evidence-secondary manifest")
    if manifest.get("label_is_human") is not False:
        raise ValueError("evidence secondary must remain non-human")
    for name, record in manifest["inputs"].items():
        verified_record(record, f"input.{name}")
    for record in manifest["evidence_cache"]:
        verified_record(record, f"cache.{record['fetch_url']}")
    for name in ("blind_worklist_d", "blind_worklist_e", "author_triage"):
        verified_record(manifest["outputs"][name], f"output.{name}")

    blind_d_path = Path(manifest["outputs"]["blind_worklist_d"]["path"])
    blind_e_path = Path(manifest["outputs"]["blind_worklist_e"]["path"])
    reviewer_d_path = Path(manifest["outputs"]["reviewer_d"])
    reviewer_e_path = Path(manifest["outputs"]["reviewer_e"])
    requests_d_path = Path(manifest["outputs"]["reviewer_d_requests"])
    requests_e_path = Path(manifest["outputs"]["reviewer_e_requests"])
    for path in (reviewer_d_path, reviewer_e_path, requests_d_path, requests_e_path):
        if not path.is_file() or path.stat().st_mtime_ns <= manifest["sealed_at_ns"]:
            raise ValueError(f"missing or pre-seal reviewer artifact: {path}")

    blind_d = load_worklist(blind_d_path)
    blind_e = load_worklist(blind_e_path)
    review_d = dual.load_unique(reviewer_d_path)
    review_e = dual.load_unique(reviewer_e_path)
    expected_ids = set(blind_d)
    if (
        len(expected_ids) != builder.EXPECTED_ROWS
        or set(blind_e) != expected_ids
        or set(review_d) != expected_ids
        or set(review_e) != expected_ids
    ):
        raise ValueError("D/E row sets differ from the sealed 37-row cohort")
    for sample_id in expected_ids:
        left = {key: value for key, value in blind_d[sample_id].items() if key != "_input_path"}
        right = {key: value for key, value in blind_e[sample_id].items() if key != "_input_path"}
        if left != right:
            raise ValueError(f"D/E blind content differs for {sample_id}")

    prompt_path = Path(manifest["inputs"]["prompt"]["path"])
    execution = manifest["review_protocol"]["execution_contract"]
    manifest_hash = dual.sha256(manifest_path)
    validated_d = {}
    validated_e = {}
    for sample_id in blind_d:
        clean_d = {key: value for key, value in blind_d[sample_id].items() if key != "_input_path"}
        clean_e = {key: value for key, value in blind_e[sample_id].items() if key != "_input_path"}
        validated_d[sample_id] = dual.validate_review(
            review_d[sample_id],
            clean_d,
            expected_pass_id=manifest["review_protocol"]["reviewer_d_pass_id"],
            expected_input_path=blind_d_path,
            expected_prompt_path=prompt_path,
            expected_manifest_path=manifest_path,
            expected_manifest_sha256=manifest_hash,
            expected_execution=execution,
        )
        validated_e[sample_id] = dual.validate_review(
            review_e[sample_id],
            clean_e,
            expected_pass_id=manifest["review_protocol"]["reviewer_e_pass_id"],
            expected_input_path=blind_e_path,
            expected_prompt_path=prompt_path,
            expected_manifest_path=manifest_path,
            expected_manifest_sha256=manifest_hash,
            expected_execution=execution,
        )

    sessions_d = {row["execution_session_id"] for row in review_d.values()}
    sessions_e = {row["execution_session_id"] for row in review_e.values()}
    if sessions_d & sessions_e:
        raise ValueError("reviewer D/E sessions overlap")
    parent_sealed = json.loads(
        Path(manifest["inputs"]["parent_sealed_manifest"]["path"]).read_text(
            encoding="utf-8"
        )
    )
    prior_paths = [
        Path(parent_sealed["inputs"]["reviewer_a"]["path"]),
        Path(parent_sealed["inputs"]["reviewer_b"]["path"]),
        Path(parent_sealed["outputs"]["reviewer_c"]),
    ]
    prior_sessions = {
        row["execution_session_id"]
        for path in prior_paths
        for row in dual.load_unique(path).values()
    }
    if (sessions_d | sessions_e) & prior_sessions:
        raise ValueError("reviewer D/E sessions overlap A/B/C sessions")

    request_logs = {
        "reviewer_d": validate_request_log(
            requests_d_path,
            blind_d,
            manifest,
            manifest["review_protocol"]["reviewer_d_pass_id"],
            sessions_d,
        ),
        "reviewer_e": validate_request_log(
            requests_e_path,
            blind_e,
            manifest,
            manifest["review_protocol"]["reviewer_e_pass_id"],
            sessions_e,
        ),
    }

    triage = dual.load_unique(Path(manifest["outputs"]["author_triage"]["path"]))
    citation_fields = set(manifest["review_protocol"]["citation_required_fields"])
    secondary_rows = []
    strict_count = 0
    strict_by_field = Counter()
    strict_by_group = Counter()
    for sample_id in blind_d:
        clean_blind = {key: value for key, value in blind_d[sample_id].items() if key != "_input_path"}
        left = validated_d[sample_id]
        right = validated_e[sample_id]
        citation_required = clean_blind["field"] in citation_fields
        left_citation = citation_passed(left, clean_blind, citation_required)
        right_citation = citation_passed(right, clean_blind, citation_required)
        base_strict = dual.is_strict_consensus(left, right)
        strict = base_strict and left_citation and right_citation
        strict_count += int(strict)
        strict_by_field[clean_blind["field"]] += int(strict)
        group = triage[sample_id]["selection_group"]
        strict_by_group[group] += int(strict)
        secondary_rows.append(
            {
                "sample_id": sample_id,
                "cve_id": clean_blind["cve_id"],
                "field": clean_blind["field"],
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "prior_vote_group": group,
                "successful_evidence_urls": sorted(successful_urls(clean_blind)),
                "exact_label_agreement": left["discrepancy_label"] == right["discrepancy_label"],
                "base_strict_consensus": base_strict,
                "reviewer_d_citation_passed": left_citation,
                "reviewer_e_citation_passed": right_citation,
                "secondary_strict_consensus": strict,
                "secondary_consensus_label": left["discrepancy_label"] if strict else None,
                "reviewer_d": left,
                "reviewer_e": right,
            }
        )

    secondary_by_id = {row["sample_id"]: row for row in secondary_rows}
    parent_rows = list(
        dual.iter_jsonl(Path(manifest["inputs"]["parent_candidate"]["path"]))
    )
    if len(parent_rows) != EXPECTED_TOTAL_ROWS:
        raise ValueError("parent candidate row count drift")
    if sum(row["candidate_resolved"] for row in parent_rows) != EXPECTED_PARENT_CANDIDATES:
        raise ValueError("parent candidate coverage drift")
    combined_rows = []
    for parent in parent_rows:
        secondary = secondary_by_id.get(parent["sample_id"])
        if parent["candidate_resolved"]:
            candidate_label = parent["candidate_label"]
            resolution = parent["resolution"]
        elif secondary and secondary["secondary_strict_consensus"]:
            candidate_label = secondary["secondary_consensus_label"]
            resolution = "evidence_secondary_strict_de"
        else:
            candidate_label = None
            resolution = "unresolved_after_evidence_secondary"
        combined_rows.append(
            {
                **parent,
                "candidate_label": candidate_label,
                "candidate_resolved": candidate_label is not None,
                "resolution": resolution,
                "evidence_secondary": secondary,
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
            }
        )
    combined_count = sum(row["candidate_resolved"] for row in combined_rows)
    if combined_count != EXPECTED_PARENT_CANDIDATES + strict_count:
        raise ValueError("combined candidate count does not equal parent plus secondary")

    evidence_rate = manifest["evidence"]["successful_nonempty_evidence_rate"]
    gate = build_gate(evidence_rate, strict_count, combined_count)
    per_field = {}
    for field, selected in builder.EXPECTED_FIELD_COUNTS.items():
        per_field[field] = {
            "selected_rows": selected,
            "secondary_strict_rows": strict_by_field[field],
            "secondary_strict_rate": strict_by_field[field] / selected,
        }
    per_group = {}
    for group, selected in builder.EXPECTED_GROUP_COUNTS.items():
        per_group[group] = {
            "selected_rows": selected,
            "secondary_strict_rows": strict_by_group[group],
            "secondary_strict_rate": strict_by_group[group] / selected,
        }
    summary = {
        "schema_version": builder.SCHEMA_VERSION,
        "artifact_type": "rq2_typing_unresolved_evidence_secondary_summary",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "selected_rows": builder.EXPECTED_ROWS,
        "rows_with_successful_evidence": manifest["evidence"]["rows_with_successful_nonempty_evidence"],
        "evidence_availability_rate": evidence_rate,
        "exact_label_agreement_rows": sum(row["exact_label_agreement"] for row in secondary_rows),
        "base_strict_rows": sum(row["base_strict_consensus"] for row in secondary_rows),
        "secondary_strict_rows": strict_count,
        "secondary_strict_resolution_rate": strict_count / builder.EXPECTED_ROWS,
        "total_rows": EXPECTED_TOTAL_ROWS,
        "parent_candidate_rows": EXPECTED_PARENT_CANDIDATES,
        "combined_candidate_rows": combined_count,
        "combined_candidate_coverage": combined_count / EXPECTED_TOTAL_ROWS,
        "remaining_unresolved_rows": EXPECTED_TOTAL_ROWS - combined_count,
        "per_field": per_field,
        "per_prior_vote_group": per_group,
        "candidate_label_counts": dict(
            sorted(
                Counter(
                    row["candidate_label"]
                    for row in combined_rows
                    if row["candidate_label"] is not None
                ).items()
            )
        ),
        "reviewer_request_logs": request_logs,
        "advancement_gate": gate,
        "boundary": manifest["boundary"],
    }
    predictions = dual.load_unique(Path(manifest["inputs"]["predictions"]["path"]))
    metrics = candidate_metrics(combined_rows, predictions)

    output_dir.mkdir(parents=True, exist_ok=False)
    secondary_path = output_dir / "dual_review_consensus.jsonl"
    combined_path = output_dir / "combined_expert_candidate.jsonl"
    summary_path = output_dir / "summary.json"
    metrics_path = output_dir / "baseline_candidate_agreement.json"
    markdown_path = output_dir / "summary.md"
    result_manifest_path = output_dir / "manifest.json"
    write_jsonl(secondary_path, secondary_rows)
    write_jsonl(combined_path, combined_rows)
    write_json(summary_path, summary)
    write_json(metrics_path, metrics)
    markdown_path.write_text(render_markdown(summary, metrics), encoding="utf-8")
    result_manifest = {
        "schema_version": builder.SCHEMA_VERSION,
        "artifact_type": "rq2_typing_unresolved_evidence_secondary_result_manifest",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "inputs": {
            "sealed_manifest": {"path": str(manifest_path), "sha256": dual.sha256(manifest_path)},
            "reviewer_d": {"path": str(reviewer_d_path), "sha256": dual.sha256(reviewer_d_path)},
            "reviewer_e": {"path": str(reviewer_e_path), "sha256": dual.sha256(reviewer_e_path)},
            "reviewer_d_requests": {"path": str(requests_d_path), "sha256": dual.sha256(requests_d_path)},
            "reviewer_e_requests": {"path": str(requests_e_path), "sha256": dual.sha256(requests_e_path)},
            "merge_code": {"path": str(Path(__file__).resolve()), "sha256": dual.sha256(Path(__file__).resolve())},
        },
        "outputs": {
            "secondary_consensus": {"path": str(secondary_path), "sha256": dual.sha256(secondary_path)},
            "combined_candidate": {"path": str(combined_path), "sha256": dual.sha256(combined_path)},
            "summary": {"path": str(summary_path), "sha256": dual.sha256(summary_path)},
            "metrics": {"path": str(metrics_path), "sha256": dual.sha256(metrics_path)},
            "markdown": {"path": str(markdown_path), "sha256": dual.sha256(markdown_path)},
        },
        "advancement_gate": gate,
        "boundary": manifest["boundary"],
    }
    write_json(result_manifest_path, result_manifest)
    print(
        f"Evidence secondary: strict={strict_count}/{builder.EXPECTED_ROWS}; "
        f"combined={combined_count}/{EXPECTED_TOTAL_ROWS}; gate={gate['status']}"
    )
    print("Boundary: label_is_human=false; no accuracy or production claim.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
