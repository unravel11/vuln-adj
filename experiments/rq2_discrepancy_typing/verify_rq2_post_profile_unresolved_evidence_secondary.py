#!/usr/bin/env python3
"""Independently verify the post-profile 16-row evidence-secondary result."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import build_rq2_post_profile_unresolved_evidence_secondary as builder
import merge_rq2_post_profile_reviews as post_merge
import merge_rq2_typing_holdout_reviews as dual


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = (
    "results/holdout/rq2_post_profile_snapshot_v1/review/"
    "unresolved_evidence_secondary_v1/manifest.json"
)
EXPECTED_TOTAL = 250
EXPECTED_MAIN_STRICT = 231
EXPECTED_CWE_ADDITIONS = 3


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def verified(record: dict, name: str) -> Path:
    path = Path(record["path"])
    if not path.is_file() or dual.sha256(path) != record.get("sha256"):
        raise ValueError(f"hash or path mismatch for {name}: {path}")
    return path


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def successful_urls(blind: dict) -> set[str]:
    return {
        row["url"]
        for row in (blind.get("evidence_context") or {}).get("records", [])
        if row.get("fetch_status") == "ok" and str(row.get("text_snippet") or "").strip()
    }


def strict_pair(left: dict, right: dict, blind: dict, citation_required: bool) -> bool:
    strict = (
        left["discrepancy_label"] == right["discrepancy_label"]
        and left["discrepancy_label"] != "uncertain"
        and left["confidence"] != "low"
        and right["confidence"] != "low"
        and left["needs_human_review"] is False
        and right["needs_human_review"] is False
    )
    if not strict or not citation_required:
        return strict
    urls = successful_urls(blind)
    return bool(set(left["evidence_urls"]) & urls) and bool(set(right["evidence_urls"]) & urls)


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


def expected_gate(evidence_rate: float, strict_count: int, combined_count: int) -> dict:
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


def validate(result_manifest: dict) -> dict:
    if result_manifest.get("artifact_type") != "rq2_post_profile_unresolved_evidence_secondary_result_manifest_v1":
        raise ValueError("unexpected result manifest")
    if result_manifest.get("label_is_human") is not False:
        raise ValueError("result must remain non-human")
    inputs = {
        name: verified(record, f"result.input.{name}")
        for name, record in result_manifest["inputs"].items()
    }
    outputs = {
        name: verified(record, f"result.output.{name}")
        for name, record in result_manifest["outputs"].items()
    }
    sealed_path = inputs["sealed_manifest"]
    sealed = load_json(sealed_path)
    if sealed.get("artifact_type") != "rq2_post_profile_unresolved_evidence_secondary_manifest_v1":
        raise ValueError("unexpected sealed manifest")
    if sealed.get("selected_rows") != builder.EXPECTED_ROWS:
        raise ValueError("selected-row count drift")
    sealed_inputs = {}
    for name, record in sealed["inputs"].items():
        if name == "prior_reviewers":
            continue
        sealed_inputs[name] = verified(record, f"sealed.input.{name}")
    prior_paths = {
        name: verified(record, f"sealed.input.prior_reviewers.{name}")
        for name, record in sealed["inputs"]["prior_reviewers"].items()
    }
    for row in sealed["evidence_cache"]:
        verified(row, f"sealed.cache.{row['fetch_url']}")
    worklist_g_path = verified(sealed["outputs"]["blind_worklist_g"], "sealed.worklist_g")
    worklist_h_path = verified(sealed["outputs"]["blind_worklist_h"], "sealed.worklist_h")
    verified(sealed["outputs"]["author_triage"], "sealed.author_triage")

    blind_g = dual.load_unique(worklist_g_path)
    blind_h = dual.load_unique(worklist_h_path)
    review_g = dual.load_unique(inputs["reviewer_g"])
    review_h = dual.load_unique(inputs["reviewer_h"])
    ids = set(blind_g)
    if len(ids) != builder.EXPECTED_ROWS or any(set(rows) != ids for rows in (blind_h, review_g, review_h)):
        raise ValueError("G/H row-set drift")
    if list(blind_h) != list(reversed(list(blind_g))):
        raise ValueError("opposite input order drift")
    if any(blind_g[sample_id] != blind_h[sample_id] for sample_id in ids):
        raise ValueError("blind content drift")
    if dict(sorted(Counter(row["field"] for row in blind_g.values()).items())) != builder.EXPECTED_FIELD_COUNTS:
        raise ValueError("field-count drift")

    prompt_path = sealed_inputs["prompt"]
    execution = sealed["review_protocol"]["execution_contract"]
    sealed_hash = dual.sha256(sealed_path)
    annotation_g = {}
    annotation_h = {}
    for sample_id in blind_g:
        annotation_g[sample_id] = dual.validate_review(
            review_g[sample_id], blind_g[sample_id],
            expected_pass_id=sealed["review_protocol"]["reviewer_g_pass_id"],
            expected_input_path=worklist_g_path, expected_prompt_path=prompt_path,
            expected_manifest_path=sealed_path, expected_manifest_sha256=sealed_hash,
            expected_execution=execution,
        )
        annotation_h[sample_id] = dual.validate_review(
            review_h[sample_id], blind_h[sample_id],
            expected_pass_id=sealed["review_protocol"]["reviewer_h_pass_id"],
            expected_input_path=worklist_h_path, expected_prompt_path=prompt_path,
            expected_manifest_path=sealed_path, expected_manifest_sha256=sealed_hash,
            expected_execution=execution,
        )
    logs = {}
    sessions = {}
    for suffix, review, worklist_path in (
        ("g", review_g, worklist_g_path), ("h", review_h, worklist_h_path)
    ):
        request_path = inputs[f"reviewer_{suffix}_requests"]
        sessions[suffix] = {row["execution_session_id"] for row in review.values()}
        audit = post_merge.audit_request_log(
            request_path,
            pass_id=sealed["review_protocol"][f"reviewer_{suffix}_pass_id"],
            expected_samples=ids,
            execution=execution,
            input_hash=dual.sha256(worklist_path),
            prompt_hash=dual.sha256(prompt_path),
            manifest_hash=sealed_hash,
        )
        if sessions[suffix] != audit["session_ids"]:
            raise ValueError(f"reviewer {suffix.upper()} session drift")
        logs[f"reviewer_{suffix}"] = {
            key: value for key, value in audit.items() if key != "session_ids"
        }
    prior_sessions = {
        session
        for name, path in prior_paths.items()
        if name.startswith("main_")
        for session in review_sessions(path)
    }
    cwe_merge = load_json(sealed_inputs["cwe_merge_manifest"])
    for name in ("requests_e", "requests_f"):
        path = verified(cwe_merge["inputs"][name], f"cwe_merge.input.{name}")
        prior_sessions.update(request_sessions(path))
    if sessions["g"] & sessions["h"] or (sessions["g"] | sessions["h"]) & prior_sessions:
        raise ValueError("review session overlap")

    citation_fields = set(sealed["review_protocol"]["citation_required_fields"])
    expected_secondary = {}
    strict_by_field = Counter()
    for sample_id in blind_g:
        strict = strict_pair(
            annotation_g[sample_id], annotation_h[sample_id], blind_g[sample_id],
            blind_g[sample_id]["field"] in citation_fields,
        )
        strict_by_field[blind_g[sample_id]["field"]] += int(strict)
        expected_secondary[sample_id] = {
            "strict": strict,
            "label": annotation_g[sample_id]["discrepancy_label"] if strict else None,
        }
    strict_count = sum(row["strict"] for row in expected_secondary.values())

    actual_secondary = dual.load_unique(outputs["secondary_consensus"])
    if set(actual_secondary) != ids:
        raise ValueError("secondary output row-set drift")
    for sample_id, expected in expected_secondary.items():
        row = actual_secondary[sample_id]
        if (
            row.get("label_is_human") is not False
            or row.get("secondary_strict_consensus") != expected["strict"]
            or row.get("secondary_consensus_label") != expected["label"]
        ):
            raise ValueError(f"secondary result drift: {sample_id}")

    main_rows = list(dual.iter_jsonl(sealed_inputs["main_consensus"]))
    cwe_rows = list(dual.iter_jsonl(sealed_inputs["cwe_consensus"]))
    if len(main_rows) != EXPECTED_TOTAL or sum(row["strict_consensus"] for row in main_rows) != EXPECTED_MAIN_STRICT:
        raise ValueError("main consensus drift")
    cwe_by_id = {row["original_sample_id"]: row for row in cwe_rows}
    excluded_cwe = set(sealed["excluded_cwe_rows"])
    if len(excluded_cwe) != EXPECTED_CWE_ADDITIONS:
        raise ValueError("excluded CWE drift")
    expected_staged = {}
    source_counts = Counter()
    for row in main_rows:
        sample_id = row["sample_id"]
        if row["strict_consensus"]:
            label, source = row["consensus_label"], "sealed_ab_strict"
        elif sample_id in excluded_cwe:
            cwe = cwe_by_id.get(sample_id)
            if not cwe or not cwe.get("strict_consensus"):
                raise ValueError(f"CWE addition drift: {sample_id}")
            label, source = cwe["consensus_label"], "post_selected_cwe_all50_strict"
        elif expected_secondary.get(sample_id, {}).get("strict"):
            label = expected_secondary[sample_id]["label"]
            source = "post_selected_non_cwe_evidence_strict"
        else:
            label, source = None, "unresolved"
        expected_staged[sample_id] = {"label": label, "source": source}
        source_counts[source] += 1
    combined_count = sum(row["label"] is not None for row in expected_staged.values())
    if combined_count != EXPECTED_MAIN_STRICT + EXPECTED_CWE_ADDITIONS + strict_count:
        raise ValueError("combined count conservation failure")

    staged = dual.load_unique(outputs["staged_candidate"])
    if set(staged) != set(expected_staged):
        raise ValueError("staged output row-set drift")
    for sample_id, expected in expected_staged.items():
        row = staged[sample_id]
        if (
            row.get("candidate_label") != expected["label"]
            or row.get("candidate_source") != expected["source"]
            or row.get("candidate_resolved") != (expected["label"] is not None)
            or row.get("label_is_human") is not False
        ):
            raise ValueError(f"staged candidate drift: {sample_id}")

    evidence_rate = sealed["evidence"]["successful_nonempty_evidence_rate"]
    gate = expected_gate(evidence_rate, strict_count, combined_count)
    summary = load_json(outputs["summary"])
    if (
        summary.get("secondary_strict_rows") != strict_count
        or summary.get("combined_candidate_rows") != combined_count
        or summary.get("candidate_source_counts") != dict(sorted(source_counts.items()))
        or summary.get("reviewer_request_logs") != logs
        or summary.get("advancement_gate") != gate
    ):
        raise ValueError("summary recomputation drift")

    predictions = dual.load_unique(sealed_inputs["predictions"])
    profiles = sorted(
        key
        for key in next(iter(predictions.values()))
        if key not in {"sample_id", "cve_id", "field"}
    )
    metrics = load_json(outputs["metrics"])
    for profile in profiles:
        matches = sum(
            predictions[sample_id][profile] == row["label"]
            for sample_id, row in expected_staged.items()
            if row["label"] is not None
        )
        if metrics["profiles"][profile]["agreement_count"] != matches:
            raise ValueError(f"profile agreement drift: {profile}")
    if metrics.get("candidate_rows") != combined_count:
        raise ValueError("metric candidate count drift")
    if result_manifest.get("advancement_gate") != gate:
        raise ValueError("result-manifest gate drift")
    return {
        "selected_rows": builder.EXPECTED_ROWS,
        "secondary_strict_rows": strict_count,
        "combined_candidate_rows": combined_count,
        "remaining_unresolved_rows": EXPECTED_TOTAL - combined_count,
        "gate": gate["status"],
    }


def main() -> int:
    manifest_path = resolve(parse_args().manifest)
    result = validate(load_json(manifest_path))
    print(
        "Verified post-profile unresolved evidence secondary: "
        f"selected={result['selected_rows']} strict={result['secondary_strict_rows']} "
        f"combined={result['combined_candidate_rows']} "
        f"remaining={result['remaining_unresolved_rows']} gate={result['gate']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
