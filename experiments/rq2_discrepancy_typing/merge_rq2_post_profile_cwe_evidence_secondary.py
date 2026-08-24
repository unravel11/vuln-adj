#!/usr/bin/env python3
"""Validate and merge two v3 post-profile CWE evidence-secondary reviews."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ANNOTATION_DIR = (
    "data/annotations/holdout/rq2_post_profile_snapshot_v1/"
    "cwe_evidence_secondary_v3"
)
DEFAULT_MANIFEST = f"{DEFAULT_ANNOTATION_DIR}/manifest.sealed.json"
DEFAULT_REVIEWER_C = f"{DEFAULT_ANNOTATION_DIR}/reviewer_c.jsonl"
DEFAULT_REVIEWER_D = f"{DEFAULT_ANNOTATION_DIR}/reviewer_d.jsonl"
DEFAULT_REQUESTS_C = f"{DEFAULT_ANNOTATION_DIR}/reviewer_c.requests.jsonl"
DEFAULT_REQUESTS_D = f"{DEFAULT_ANNOTATION_DIR}/reviewer_d.requests.jsonl"
DEFAULT_OUTPUT_DIR = (
    "results/holdout/rq2_post_profile_snapshot_v1/review/"
    "cwe_evidence_secondary_v3"
)
REVIEW_KEYS = {
    "reviewer_id",
    "run_id",
    "review_id",
    "cve_id",
    "set_relation",
    "discrepancy_label",
    "taxonomy_support_verdict",
    "specific_mapping_verdict",
    "confidence",
    "needs_additional_review",
    "rationale",
    "supporting_cwe_paths",
    "supporting_evidence",
}
LABEL_VERDICT = {
    "representation_discrepancy": (
        "supports_granularity_only",
        "same_mechanism_supported",
    ),
    "factual_conflict": (
        "does_not_support_granularity_only",
        "materially_different_or_contradicted",
    ),
    "uncertain": ("insufficient", "insufficient"),
}
STRICT_KEYS = (
    "set_relation",
    "discrepancy_label",
    "taxonomy_support_verdict",
    "specific_mapping_verdict",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--reviewer-c", default=DEFAULT_REVIEWER_C)
    parser.add_argument("--reviewer-d", default=DEFAULT_REVIEWER_D)
    parser.add_argument("--requests-c", default=DEFAULT_REQUESTS_C)
    parser.add_argument("--requests-d", default=DEFAULT_REQUESTS_D)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{line_number}") from exc


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def load_unique(path: Path, key: str) -> dict[str, dict]:
    rows = {}
    for row in iter_jsonl(path):
        value = row[key]
        if value in rows:
            raise ValueError(f"duplicate {key}={value} in {path}")
        rows[value] = row
    return rows


def allowed_paths(source: dict) -> set[str]:
    result = set()
    relations = source["official_taxonomy"]["relation_profile"][
        "ancestor_descendant_paths"
    ]
    for relation in relations:
        path = ">".join(item["cwe_id"] for item in relation["path"])
        result.add(path)
    return result


def evidence_by_url(source: dict) -> dict[str, str]:
    return {
        record["source_url"]: record["text_snippet"]
        for record in source["evidence_context"]["records"]
        if record.get("fetch_status") == "ok" and record.get("text_snippet")
    }


def validate_reviews(
    path: Path,
    worklist_path: Path,
    expected_reviewer_id: str,
) -> list[dict]:
    worklist = list(iter_jsonl(worklist_path))
    reviews = list(iter_jsonl(path))
    if len(reviews) != len(worklist):
        raise ValueError(f"review row count mismatch: {len(reviews)} != {len(worklist)}")
    run_ids = set()
    for index, (review, source) in enumerate(zip(reviews, worklist), start=1):
        if set(review) != REVIEW_KEYS:
            raise ValueError(f"review schema mismatch at {path}:{index}")
        if review["reviewer_id"] != expected_reviewer_id:
            raise ValueError(f"reviewer identity mismatch at {path}:{index}")
        if not isinstance(review["run_id"], str) or not review["run_id"].strip():
            raise ValueError(f"blank run_id at {path}:{index}")
        run_ids.add(review["run_id"])
        for key in ("review_id", "cve_id"):
            if review[key] != source[key]:
                raise ValueError(f"identity mismatch for {key} at {path}:{index}")
        contract = source["review_contract"]
        for key in (
            "set_relation",
            "discrepancy_label",
            "taxonomy_support_verdict",
            "specific_mapping_verdict",
            "confidence",
        ):
            if review[key] not in contract[key]:
                raise ValueError(f"invalid {key} at {path}:{index}")
        expected_taxonomy, expected_mapping = LABEL_VERDICT[review["discrepancy_label"]]
        if review["taxonomy_support_verdict"] != expected_taxonomy:
            raise ValueError(f"label/taxonomy mismatch at {path}:{index}")
        if review["specific_mapping_verdict"] != expected_mapping:
            raise ValueError(f"label/mapping mismatch at {path}:{index}")
        if not isinstance(review["needs_additional_review"], bool):
            raise ValueError(f"needs_additional_review is not boolean at {path}:{index}")
        if review["discrepancy_label"] == "uncertain" and (
            review["confidence"] != "low" or not review["needs_additional_review"]
        ):
            raise ValueError(f"uncertain row violates fail-closed contract at {path}:{index}")
        if review["discrepancy_label"] != "uncertain" and (
            review["confidence"] not in {"high", "medium"}
            or review["needs_additional_review"]
        ):
            raise ValueError(f"determinate row violates v2 contract at {path}:{index}")
        if review["confidence"] == "low" and not review["needs_additional_review"]:
            raise ValueError(f"low confidence must request review at {path}:{index}")
        if not isinstance(review["rationale"], str) or len(review["rationale"].strip()) < 120:
            raise ValueError(f"rationale too short at {path}:{index}")

        paths = review["supporting_cwe_paths"]
        if not isinstance(paths, list) or any(not isinstance(item, str) for item in paths):
            raise ValueError(f"invalid supporting_cwe_paths at {path}:{index}")
        if len(paths) != len(set(paths)) or set(paths) - allowed_paths(source):
            raise ValueError(f"unknown supporting CWE path at {path}:{index}")
        if review["discrepancy_label"] == "representation_discrepancy" and not paths:
            raise ValueError(f"representation decision lacks CWE path at {path}:{index}")

        citations = review["supporting_evidence"]
        if not isinstance(citations, list):
            raise ValueError(f"supporting_evidence is not a list at {path}:{index}")
        if review["discrepancy_label"] != "uncertain" and not citations:
            raise ValueError(f"determinate decision lacks frozen evidence at {path}:{index}")
        available = evidence_by_url(source)
        seen = set()
        for citation in citations:
            if not isinstance(citation, dict) or set(citation) != {"url", "quote"}:
                raise ValueError(f"citation schema mismatch at {path}:{index}")
            url, quote = citation["url"], citation["quote"]
            if url not in available:
                raise ValueError(f"citation URL not in successful evidence at {path}:{index}")
            if not isinstance(quote, str) or not 20 <= len(quote) <= 280:
                raise ValueError(f"citation quote length invalid at {path}:{index}")
            if quote not in available[url]:
                raise ValueError(f"citation is not a literal frozen substring at {path}:{index}")
            marker = (url, quote)
            if marker in seen:
                raise ValueError(f"duplicate citation at {path}:{index}")
            seen.add(marker)
    if len(run_ids) != 1:
        raise ValueError(f"review file must contain one run_id: {path}")
    return reviews


def validate_request_log(
    path: Path,
    expected_reviewer_id: str,
    expected_output: Path,
    expected_worklist: Path,
    expected_run_id: str,
) -> dict:
    records = list(iter_jsonl(path))
    if len(records) != 1:
        raise ValueError(f"expected one request record in {path}")
    record = records[0]
    if record.get("reviewer_id") != expected_reviewer_id:
        raise ValueError(f"request reviewer mismatch in {path}")
    if record.get("run_id") != expected_run_id:
        raise ValueError(f"request run_id mismatch in {path}")
    if record.get("label_is_human") is not False:
        raise ValueError(f"request log human-label boundary violated in {path}")
    if record.get("row_count") != 3:
        raise ValueError(f"request row count mismatch in {path}")
    for key, expected in (("output", expected_output), ("worklist", expected_worklist)):
        entry = record.get(key) or {}
        if entry.get("path") != str(expected) or entry.get("sha256") != sha256(expected):
            raise ValueError(f"request {key} binding mismatch in {path}")
    if not record.get("session_id"):
        raise ValueError(f"request session_id missing in {path}")
    return record


def strict_consensus(left: dict, right: dict) -> tuple[bool, str | None]:
    exact = all(left[key] == right[key] for key in STRICT_KEYS)
    strict = (
        exact
        and left["discrepancy_label"] != "uncertain"
        and not left["needs_additional_review"]
        and not right["needs_additional_review"]
    )
    return strict, left["discrepancy_label"] if strict else None


def render_markdown(summary: dict) -> str:
    lines = [
        "# Post-Profile CWE Evidence-Secondary Diagnostic",
        "",
        "This is a post-selection, non-human diagnostic over three profile-difference rows. It is not human gold or a confirmatory gain estimate.",
        "",
        f"- Strict evidence consensus: `{summary['strict_rows']}/{summary['rows']}`.",
        f"- Candidate-direction strict rows: `{summary['candidate_direction_strict_rows']}`.",
        f"- Current-direction strict rows: `{summary['current_direction_strict_rows']}`.",
        f"- Previously non-strict rows resolved: `{summary['resolved_prior_non_strict_rows']}/{summary['prior_non_strict_rows']}`.",
        "",
        "| CVE | Prior strict | Evidence C | Evidence D | Evidence strict | Direction |",
        "|---|---:|---|---|---:|---|",
    ]
    for row in summary["case_rows"]:
        lines.append(
            f"| {row['cve_id']} | {str(row['prior_strict_consensus']).lower()} | "
            f"{row['reviewer_c_label']} | {row['reviewer_d_label']} | "
            f"{str(row['strict_consensus']).lower()} | {row['profile_direction']} |"
        )
    lines.extend(
        [
            "",
            "The sealed 250-row evaluation is unchanged. Candidate promotion and production switching remain disabled.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    manifest_path = resolve(args.manifest)
    reviewer_c_path = resolve(args.reviewer_c)
    reviewer_d_path = resolve(args.reviewer_d)
    requests_c_path = resolve(args.requests_c)
    requests_d_path = resolve(args.requests_d)
    output_dir = resolve(args.output_dir)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("artifact_type") != "rq2_post_profile_cwe_evidence_secondary_manifest_v3":
        raise ValueError("unexpected evidence-secondary manifest")
    if manifest.get("row_count") != 3:
        raise ValueError("evidence-secondary manifest must contain three rows")
    if manifest["selection"].get("supersedes_failed_v1_contract_attempt") is not True:
        raise ValueError("v3 manifest does not bind the failed v1 attempt")
    if manifest["selection"].get("supersedes_failed_v2_path_contract_attempt") is not True:
        raise ValueError("v3 manifest does not bind the failed v2 attempt")
    for entry in manifest["inputs"].values():
        path = Path(entry["path"])
        if sha256(path) != entry["sha256"]:
            raise ValueError(f"sealed input changed: {path}")
    if sha256(Path(manifest["builder"]["path"])) != manifest["builder"]["sha256"]:
        raise ValueError("builder changed after sealing")

    worklist_c_path = Path(manifest["worklists"]["reviewer_c"]["path"])
    worklist_d_path = Path(manifest["worklists"]["reviewer_d"]["path"])
    for key, path in (("reviewer_c", worklist_c_path), ("reviewer_d", worklist_d_path)):
        if sha256(path) != manifest["worklists"][key]["sha256"]:
            raise ValueError(f"sealed worklist changed: {key}")
    if [row["review_id"] for row in iter_jsonl(worklist_d_path)] != list(
        reversed([row["review_id"] for row in iter_jsonl(worklist_c_path)])
    ):
        raise ValueError("reviewer D worklist is not exact reverse order")

    reviews_c = validate_reviews(
        reviewer_c_path, worklist_c_path, "codex_post_profile_cwe_evidence_v3_c"
    )
    reviews_d = validate_reviews(
        reviewer_d_path, worklist_d_path, "codex_post_profile_cwe_evidence_v3_d"
    )
    by_id_c = {row["review_id"]: row for row in reviews_c}
    by_id_d = {row["review_id"]: row for row in reviews_d}
    if set(by_id_c) != set(by_id_d):
        raise ValueError("reviewer target sets differ")
    run_id_c = reviews_c[0]["run_id"]
    run_id_d = reviews_d[0]["run_id"]
    if run_id_c == run_id_d:
        raise ValueError("reviewer run IDs are not independent")
    request_c = validate_request_log(
        requests_c_path,
        "codex_post_profile_cwe_evidence_v3_c",
        reviewer_c_path,
        worklist_c_path,
        run_id_c,
    )
    request_d = validate_request_log(
        requests_d_path,
        "codex_post_profile_cwe_evidence_v3_d",
        reviewer_d_path,
        worklist_d_path,
        run_id_d,
    )
    if request_c["session_id"] == request_d["session_id"]:
        raise ValueError("reviewer Codex sessions are not independent")
    for path in (reviewer_c_path, reviewer_d_path, requests_c_path, requests_d_path):
        if path.stat().st_mtime_ns <= manifest["sealed_at_ns"]:
            raise ValueError(f"review artifact does not postdate seal: {path}")

    selection_by_id = {
        row["review_id"]: row for row in manifest["selection"]["rows"]
    }
    consensus_rows = []
    component_agreement = Counter()
    strict_counts = Counter()
    for source in iter_jsonl(worklist_c_path):
        review_id = source["review_id"]
        left, right = by_id_c[review_id], by_id_d[review_id]
        for key in STRICT_KEYS:
            component_agreement[key] += int(left[key] == right[key])
        strict, label = strict_consensus(left, right)
        if label:
            strict_counts[label] += 1
        selection = selection_by_id[review_id]
        if strict and label == selection["candidate"]:
            direction = "candidate"
        elif strict and label == selection["current"]:
            direction = "current"
        elif strict:
            direction = "neither"
        else:
            direction = "unresolved"
        consensus_rows.append(
            {
                "review_id": review_id,
                "original_sample_id": source["original_sample_id"],
                "cve_id": source["cve_id"],
                "field": "cwe_ids",
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "strict_consensus": strict,
                "consensus_label": label,
                "profile_direction": direction,
                "selection": selection,
                "reviewer_c": left,
                "reviewer_d": right,
            }
        )

    strict_rows = sum(row["strict_consensus"] for row in consensus_rows)
    prior_non_strict_rows = sum(
        not row["selection"]["prior_strict_consensus"] for row in consensus_rows
    )
    resolved_prior_non_strict = sum(
        row["strict_consensus"] and not row["selection"]["prior_strict_consensus"]
        for row in consensus_rows
    )
    case_rows = [
        {
            "review_id": row["review_id"],
            "cve_id": row["cve_id"],
            "prior_strict_consensus": row["selection"]["prior_strict_consensus"],
            "reviewer_c_label": row["reviewer_c"]["discrepancy_label"],
            "reviewer_d_label": row["reviewer_d"]["discrepancy_label"],
            "strict_consensus": row["strict_consensus"],
            "consensus_label": row["consensus_label"],
            "profile_direction": row["profile_direction"],
        }
        for row in consensus_rows
    ]
    summary = {
        "artifact_type": "rq2_post_profile_cwe_evidence_secondary_summary_v3",
        "rows": len(consensus_rows),
        "strict_rows": strict_rows,
        "strict_coverage": strict_rows / len(consensus_rows),
        "strict_label_counts": dict(sorted(strict_counts.items())),
        "component_exact_agreement": {
            key: {"count": component_agreement[key], "rows": len(consensus_rows)}
            for key in STRICT_KEYS
        },
        "prior_strict_rows": len(consensus_rows) - prior_non_strict_rows,
        "prior_non_strict_rows": prior_non_strict_rows,
        "resolved_prior_non_strict_rows": resolved_prior_non_strict,
        "candidate_direction_strict_rows": sum(
            row["profile_direction"] == "candidate" for row in consensus_rows
        ),
        "current_direction_strict_rows": sum(
            row["profile_direction"] == "current" for row in consensus_rows
        ),
        "neither_direction_strict_rows": sum(
            row["profile_direction"] == "neither" for row in consensus_rows
        ),
        "unresolved_rows": sum(
            row["profile_direction"] == "unresolved" for row in consensus_rows
        ),
        "case_rows": case_rows,
        "reviewer_sessions_disjoint": True,
        "post_selection_profile_differential": True,
        "selected_after_a_b_unsealing": True,
        **manifest["claim_boundary"],
        "sealed_250_row_evaluation_changed": False,
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    consensus_path = output_dir / "dual_review_consensus.jsonl"
    summary_path = output_dir / "summary.json"
    summary_md_path = output_dir / "summary.md"
    merge_manifest_path = output_dir / "merge_manifest.json"
    write_jsonl(consensus_path, consensus_rows)
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    summary_md_path.write_text(render_markdown(summary), encoding="utf-8")
    merge_manifest = {
        "artifact_type": "rq2_post_profile_cwe_evidence_secondary_merge_manifest_v3",
        "source_manifest": {"path": str(manifest_path), "sha256": sha256(manifest_path)},
        "review_inputs": {
            "reviewer_c": {"path": str(reviewer_c_path), "sha256": sha256(reviewer_c_path)},
            "reviewer_d": {"path": str(reviewer_d_path), "sha256": sha256(reviewer_d_path)},
            "requests_c": {"path": str(requests_c_path), "sha256": sha256(requests_c_path)},
            "requests_d": {"path": str(requests_d_path), "sha256": sha256(requests_d_path)},
        },
        "outputs": {
            "consensus": {"path": str(consensus_path), "sha256": sha256(consensus_path)},
            "summary": {"path": str(summary_path), "sha256": sha256(summary_path)},
            "summary_md": {"path": str(summary_md_path), "sha256": sha256(summary_md_path)},
        },
        "claim_boundary": manifest["claim_boundary"],
    }
    merge_manifest_path.write_text(
        json.dumps(merge_manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {consensus_path}")
    print(f"Wrote {summary_path}")
    print(f"Wrote {merge_manifest_path}")
    print(
        f"strict={strict_rows}/{len(consensus_rows)} "
        f"candidate={summary['candidate_direction_strict_rows']} "
        f"current={summary['current_direction_strict_rows']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
