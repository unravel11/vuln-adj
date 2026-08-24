#!/usr/bin/env python3
"""Merge the 16-row post-profile unresolved evidence-secondary G/H review."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import build_rq2_post_profile_unresolved_evidence_secondary as builder
import merge_rq2_post_profile_reviews as post_merge
import merge_rq2_typing_holdout_reviews as dual


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASE = builder.DEFAULT_OUTPUT
DEFAULT_OUTPUT = (
    "results/holdout/rq2_post_profile_snapshot_v1/review/"
    "unresolved_evidence_secondary_v1"
)
EXPECTED_MAIN_STRICT = 231
EXPECTED_CWE_ADDITIONS = 3
EXPECTED_TOTAL = 250


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-dir", default=DEFAULT_BASE)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def verified(record: dict, name: str) -> Path:
    path = Path(record["path"])
    if not path.is_file() or dual.sha256(path) != record.get("sha256"):
        raise ValueError(f"hash or path mismatch for {name}: {path}")
    return path


def successful_urls(blind: dict) -> set[str]:
    return {
        row["url"]
        for row in (blind.get("evidence_context") or {}).get("records", [])
        if row.get("fetch_status") == "ok" and str(row.get("text_snippet") or "").strip()
    }


def strict_secondary(left: dict, right: dict, blind: dict, citation_required: bool) -> bool:
    if not dual.is_strict_consensus(left, right):
        return False
    if not citation_required:
        return True
    urls = successful_urls(blind)
    return bool(set(left["evidence_urls"]) & urls) and bool(set(right["evidence_urls"]) & urls)


def successful_request_order(path: Path) -> list[str]:
    events = list(post_merge.iter_jsonl(path))
    pending: list[list[str]] = []
    order: list[str] = []
    for event in events:
        ids = [item.get("sample_id") for item in event.get("items") or []]
        if event.get("event_type") == "request":
            pending.append(ids)
        elif event.get("event_type") == "response_success":
            response_ids = event.get("sample_ids") or []
            match = next((i for i in range(len(pending) - 1, -1, -1) if pending[i] == response_ids), None)
            if match is None:
                raise ValueError(f"{path}: success lacks matching request")
            pending.pop(match)
            order.extend(response_ids)
    return order


def review_sessions(path: Path) -> set[str]:
    sessions = {
        row.get("execution_session_id") for row in dual.iter_jsonl(path)
    }
    if None in sessions or "" in sessions:
        raise ValueError(f"{path}: reviewer row lacks execution session")
    return sessions


def request_sessions(path: Path) -> set[str]:
    sessions = {row.get("session_id") for row in dual.iter_jsonl(path)}
    if None in sessions or "" in sessions:
        raise ValueError(f"{path}: request row lacks session_id")
    return sessions


def build_gate(evidence_rate: float, strict_count: int, combined_count: int) -> dict:
    checks = {
        "minimum_evidence_availability": evidence_rate >= builder.MIN_EVIDENCE_AVAILABILITY,
        "minimum_secondary_strict_resolution": (
            strict_count / builder.EXPECTED_ROWS >= builder.MIN_SECONDARY_STRICT_RESOLUTION
        ),
        "minimum_combined_candidate_coverage": (
            combined_count / EXPECTED_TOTAL >= builder.MIN_COMBINED_CANDIDATE_COVERAGE
        ),
        "non_human_boundary_preserved": True,
    }
    passed = all(checks.values())
    return {
        "status": (
            "pass_post_selected_non_human_development_only"
            if passed
            else "no_go_post_selected_non_human_evidence_secondary"
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
        "confirmatory_claim_allowed": False,
        "production_switch_allowed": False,
    }


def profile_agreement(rows: list[dict], predictions: dict[str, dict]) -> dict:
    resolved = [row for row in rows if row["candidate_label"] is not None]
    profiles = sorted(
        key
        for key in next(iter(predictions.values()))
        if key not in {"sample_id", "cve_id", "field"}
    )
    result = {}
    for profile in profiles:
        matches = sum(
            predictions[row["sample_id"]][profile] == row["candidate_label"] for row in resolved
        )
        result[profile] = {
            "candidate_rows": len(resolved),
            "agreement_count": matches,
            "agreement_on_candidate_rows": matches / len(resolved),
        }
    return {
        "rows": len(rows),
        "candidate_rows": len(resolved),
        "candidate_coverage": len(resolved) / len(rows),
        "profiles": result,
        "metric_boundary": (
            "agreement with a staged, post-selected, same-model-family non-human candidate; "
            "not human-gold accuracy or confirmatory profile performance"
        ),
    }


def render_markdown(summary: dict, metrics: dict) -> str:
    return "\n".join(
        [
            "# RQ2 Post-Profile Unresolved Evidence Secondary v1",
            "",
            "> Post-unsealing, same-model-family, non-human development diagnostic.",
            "",
            f"- Selected non-CWE rows: `{summary['selected_rows']}`",
            f"- Successful frozen evidence: `{summary['rows_with_successful_evidence']}/{summary['selected_rows']}`",
            f"- Evidence-qualified G/H strict rows: `{summary['secondary_strict_rows']}/{summary['selected_rows']}`",
            f"- Staged candidate coverage: `{summary['combined_candidate_rows']}/{summary['total_rows']}` (`{summary['combined_candidate_coverage']:.4f}`)",
            f"- Remaining unresolved rows: `{summary['remaining_unresolved_rows']}`",
            f"- Gate: `{summary['advancement_gate']['status']}`",
            "- `label_is_human=false`",
            "",
            "This result does not change the sealed 250-row evaluation and is not human-gold accuracy evidence.",
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
    if manifest.get("artifact_type") != "rq2_post_profile_unresolved_evidence_secondary_manifest_v1":
        raise ValueError("unexpected evidence-secondary manifest")
    if manifest.get("label_is_human") is not False:
        raise ValueError("evidence-secondary manifest must remain non-human")

    input_paths: dict[str, Path] = {}
    for name, record in manifest["inputs"].items():
        if name == "prior_reviewers":
            continue
        input_paths[name] = verified(record, f"input.{name}")
    prior_paths = {
        name: verified(record, f"input.prior_reviewers.{name}")
        for name, record in manifest["inputs"]["prior_reviewers"].items()
    }
    for row in manifest["evidence_cache"]:
        verified(row, f"cache.{row['fetch_url']}")
    worklist_g_path = verified(manifest["outputs"]["blind_worklist_g"], "worklist G")
    worklist_h_path = verified(manifest["outputs"]["blind_worklist_h"], "worklist H")
    triage_path = verified(manifest["outputs"]["author_triage"], "author triage")
    reviewer_g_path = Path(manifest["outputs"]["reviewer_g"])
    reviewer_h_path = Path(manifest["outputs"]["reviewer_h"])
    requests_g_path = Path(manifest["outputs"]["reviewer_g_requests"])
    requests_h_path = Path(manifest["outputs"]["reviewer_h_requests"])
    for path in (reviewer_g_path, reviewer_h_path, requests_g_path, requests_h_path):
        if not path.is_file() or path.stat().st_mtime_ns <= manifest["sealed_at_ns"]:
            raise ValueError(f"missing or pre-seal reviewer artifact: {path}")

    blind_g = dual.load_unique(worklist_g_path)
    blind_h = dual.load_unique(worklist_h_path)
    review_g = dual.load_unique(reviewer_g_path)
    review_h = dual.load_unique(reviewer_h_path)
    ids = set(blind_g)
    if len(ids) != builder.EXPECTED_ROWS or any(set(rows) != ids for rows in (blind_h, review_g, review_h)):
        raise ValueError("G/H row-set drift")
    if list(blind_h) != list(reversed(list(blind_g))):
        raise ValueError("G/H opposite-order contract drift")
    if any(blind_g[sample_id] != blind_h[sample_id] for sample_id in ids):
        raise ValueError("G/H blind-content drift")

    execution = manifest["review_protocol"]["execution_contract"]
    prompt_path = input_paths["prompt"]
    manifest_hash = dual.sha256(manifest_path)
    validated_g = {}
    validated_h = {}
    for sample_id in blind_g:
        validated_g[sample_id] = dual.validate_review(
            review_g[sample_id],
            blind_g[sample_id],
            expected_pass_id=manifest["review_protocol"]["reviewer_g_pass_id"],
            expected_input_path=worklist_g_path,
            expected_prompt_path=prompt_path,
            expected_manifest_path=manifest_path,
            expected_manifest_sha256=manifest_hash,
            expected_execution=execution,
        )
        validated_h[sample_id] = dual.validate_review(
            review_h[sample_id],
            blind_h[sample_id],
            expected_pass_id=manifest["review_protocol"]["reviewer_h_pass_id"],
            expected_input_path=worklist_h_path,
            expected_prompt_path=prompt_path,
            expected_manifest_path=manifest_path,
            expected_manifest_sha256=manifest_hash,
            expected_execution=execution,
        )

    log_g = post_merge.audit_request_log(
        requests_g_path,
        pass_id=manifest["review_protocol"]["reviewer_g_pass_id"],
        expected_samples=ids,
        execution=execution,
        input_hash=dual.sha256(worklist_g_path),
        prompt_hash=dual.sha256(prompt_path),
        manifest_hash=manifest_hash,
    )
    log_h = post_merge.audit_request_log(
        requests_h_path,
        pass_id=manifest["review_protocol"]["reviewer_h_pass_id"],
        expected_samples=ids,
        execution=execution,
        input_hash=dual.sha256(worklist_h_path),
        prompt_hash=dual.sha256(prompt_path),
        manifest_hash=manifest_hash,
    )
    if successful_request_order(requests_g_path) != list(blind_g):
        raise ValueError("reviewer G successful schedule drift")
    if successful_request_order(requests_h_path) != list(blind_h):
        raise ValueError("reviewer H successful schedule drift")
    sessions_g = {row["execution_session_id"] for row in review_g.values()}
    sessions_h = {row["execution_session_id"] for row in review_h.values()}
    if sessions_g != log_g["session_ids"] or sessions_h != log_h["session_ids"]:
        raise ValueError("review output sessions differ from request logs")
    prior_sessions = {
        session
        for name, path in prior_paths.items()
        if name.startswith("main_")
        for session in review_sessions(path)
    }
    cwe_merge = json.loads(input_paths["cwe_merge_manifest"].read_text(encoding="utf-8"))
    for name in ("requests_e", "requests_f"):
        path = verified(cwe_merge["inputs"][name], f"cwe_merge.input.{name}")
        prior_sessions.update(request_sessions(path))
    if sessions_g & sessions_h or (sessions_g | sessions_h) & prior_sessions:
        raise ValueError("G/H sessions overlap each other or prior review stages")

    citation_fields = set(manifest["review_protocol"]["citation_required_fields"])
    secondary_rows = []
    strict_by_field = Counter()
    for sample_id in blind_g:
        left = validated_g[sample_id]
        right = validated_h[sample_id]
        strict = strict_secondary(
            left, right, blind_g[sample_id], blind_g[sample_id]["field"] in citation_fields
        )
        strict_by_field[blind_g[sample_id]["field"]] += int(strict)
        secondary_rows.append(
            {
                "sample_id": sample_id,
                "cve_id": blind_g[sample_id]["cve_id"],
                "field": blind_g[sample_id]["field"],
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "successful_evidence_urls": sorted(successful_urls(blind_g[sample_id])),
                "exact_label_agreement": left["discrepancy_label"] == right["discrepancy_label"],
                "secondary_strict_consensus": strict,
                "secondary_consensus_label": left["discrepancy_label"] if strict else None,
                "reviewer_g": left,
                "reviewer_h": right,
            }
        )
    secondary_by_id = {row["sample_id"]: row for row in secondary_rows}
    strict_count = sum(row["secondary_strict_consensus"] for row in secondary_rows)

    main_rows = list(dual.iter_jsonl(input_paths["main_consensus"]))
    cwe_rows = list(dual.iter_jsonl(input_paths["cwe_consensus"]))
    if len(main_rows) != EXPECTED_TOTAL or sum(row["strict_consensus"] for row in main_rows) != EXPECTED_MAIN_STRICT:
        raise ValueError("main consensus coverage drift")
    cwe_by_id = {row["original_sample_id"]: row for row in cwe_rows}
    excluded_cwe = set(manifest["excluded_cwe_rows"])
    if len(excluded_cwe) != EXPECTED_CWE_ADDITIONS:
        raise ValueError("excluded CWE count drift")

    staged_rows = []
    source_counts = Counter()
    for row in main_rows:
        sample_id = row["sample_id"]
        if row["strict_consensus"]:
            label = row["consensus_label"]
            source = "sealed_ab_strict"
        elif sample_id in excluded_cwe:
            cwe = cwe_by_id.get(sample_id)
            if not cwe or not cwe.get("strict_consensus"):
                raise ValueError(f"missing strict CWE secondary result: {sample_id}")
            label = cwe["consensus_label"]
            source = "post_selected_cwe_all50_strict"
        else:
            secondary = secondary_by_id.get(sample_id)
            if secondary and secondary["secondary_strict_consensus"]:
                label = secondary["secondary_consensus_label"]
                source = "post_selected_non_cwe_evidence_strict"
            else:
                label = None
                source = "unresolved"
        source_counts[source] += 1
        staged_rows.append(
            {
                "sample_id": sample_id,
                "cve_id": row["cve_id"],
                "field": row["field"],
                "candidate_label": label,
                "candidate_resolved": label is not None,
                "candidate_source": source,
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
            }
        )
    combined_count = sum(row["candidate_resolved"] for row in staged_rows)
    if combined_count != EXPECTED_MAIN_STRICT + EXPECTED_CWE_ADDITIONS + strict_count:
        raise ValueError("staged candidate count conservation failure")

    evidence_rate = manifest["evidence"]["successful_nonempty_evidence_rate"]
    gate = build_gate(evidence_rate, strict_count, combined_count)
    summary = {
        "schema_version": builder.SCHEMA_VERSION,
        "artifact_type": "rq2_post_profile_unresolved_evidence_secondary_summary_v1",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "selected_rows": builder.EXPECTED_ROWS,
        "field_counts": builder.EXPECTED_FIELD_COUNTS,
        "rows_with_successful_evidence": manifest["evidence"]["rows_with_successful_nonempty_evidence"],
        "evidence_availability_rate": evidence_rate,
        "exact_label_agreement_rows": sum(row["exact_label_agreement"] for row in secondary_rows),
        "secondary_strict_rows": strict_count,
        "secondary_strict_resolution_rate": strict_count / builder.EXPECTED_ROWS,
        "secondary_strict_by_field": dict(sorted(strict_by_field.items())),
        "total_rows": EXPECTED_TOTAL,
        "parent_strict_rows": EXPECTED_MAIN_STRICT,
        "cwe_secondary_additions": EXPECTED_CWE_ADDITIONS,
        "combined_candidate_rows": combined_count,
        "combined_candidate_coverage": combined_count / EXPECTED_TOTAL,
        "remaining_unresolved_rows": EXPECTED_TOTAL - combined_count,
        "candidate_source_counts": dict(sorted(source_counts.items())),
        "reviewer_request_logs": {
            "reviewer_g": {key: value for key, value in log_g.items() if key != "session_ids"},
            "reviewer_h": {key: value for key, value in log_h.items() if key != "session_ids"},
        },
        "advancement_gate": gate,
        "boundary": manifest["boundary"],
    }
    predictions = dual.load_unique(input_paths["predictions"])
    metrics = profile_agreement(staged_rows, predictions)

    output_dir.mkdir(parents=True, exist_ok=False)
    secondary_path = output_dir / "dual_review_consensus.jsonl"
    staged_path = output_dir / "staged_expert_candidate.jsonl"
    summary_path = output_dir / "summary.json"
    metrics_path = output_dir / "profile_candidate_agreement.json"
    markdown_path = output_dir / "summary.md"
    result_manifest_path = output_dir / "manifest.json"
    dual.write_jsonl(secondary_path, secondary_rows)
    dual.write_jsonl(staged_path, staged_rows)
    write_json(summary_path, summary)
    write_json(metrics_path, metrics)
    markdown_path.write_text(render_markdown(summary, metrics), encoding="utf-8")
    result_manifest = {
        "schema_version": builder.SCHEMA_VERSION,
        "artifact_type": "rq2_post_profile_unresolved_evidence_secondary_result_manifest_v1",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "inputs": {
            "sealed_manifest": {"path": str(manifest_path), "sha256": dual.sha256(manifest_path)},
            "reviewer_g": {"path": str(reviewer_g_path), "sha256": dual.sha256(reviewer_g_path)},
            "reviewer_h": {"path": str(reviewer_h_path), "sha256": dual.sha256(reviewer_h_path)},
            "reviewer_g_requests": {"path": str(requests_g_path), "sha256": dual.sha256(requests_g_path)},
            "reviewer_h_requests": {"path": str(requests_h_path), "sha256": dual.sha256(requests_h_path)},
            "merge_code": {"path": str(Path(__file__).resolve()), "sha256": dual.sha256(Path(__file__).resolve())},
        },
        "outputs": {
            "secondary_consensus": {"path": str(secondary_path), "sha256": dual.sha256(secondary_path)},
            "staged_candidate": {"path": str(staged_path), "sha256": dual.sha256(staged_path)},
            "summary": {"path": str(summary_path), "sha256": dual.sha256(summary_path)},
            "metrics": {"path": str(metrics_path), "sha256": dual.sha256(metrics_path)},
            "markdown": {"path": str(markdown_path), "sha256": dual.sha256(markdown_path)},
        },
        "advancement_gate": gate,
        "boundary": manifest["boundary"],
    }
    write_json(result_manifest_path, result_manifest)
    print(
        f"Post-profile evidence secondary: strict={strict_count}/{builder.EXPECTED_ROWS}; "
        f"combined={combined_count}/{EXPECTED_TOTAL}; gate={gate['status']}"
    )
    print("Boundary: label_is_human=false; sealed 250-row evaluation unchanged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
