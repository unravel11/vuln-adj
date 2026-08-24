#!/usr/bin/env python3
"""Validate and merge the two post-profile all-50 CWE evidence passes."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_rq2_post_profile_cwe_all50_review as runner  # noqa: E402


BASE = "data/annotations/holdout/rq2_post_profile_snapshot_v1/cwe_all50_evidence_v3"
DEFAULT_MANIFEST = f"{BASE}/manifest.sealed.json"
DEFAULT_E = f"{BASE}/reviewer_e.jsonl"
DEFAULT_F = f"{BASE}/reviewer_f.jsonl"
DEFAULT_REQUESTS_E = f"{BASE}/reviewer_e.requests.jsonl"
DEFAULT_REQUESTS_F = f"{BASE}/reviewer_f.requests.jsonl"
DEFAULT_OUTPUT = (
    "results/holdout/rq2_post_profile_snapshot_v1/review/"
    "cwe_all50_evidence_v3"
)
REVIEW_KEYS = runner.ITEM_KEYS | {"reviewer_id", "run_id"}
STRICT_KEYS = (
    "set_relation",
    "discrepancy_label",
    "taxonomy_compatibility",
    "specific_mapping_verdict",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--reviewer-e", default=DEFAULT_E)
    parser.add_argument("--reviewer-f", default=DEFAULT_F)
    parser.add_argument("--requests-e", default=DEFAULT_REQUESTS_E)
    parser.add_argument("--requests-f", default=DEFAULT_REQUESTS_F)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT)
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


def canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


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


def evidence_by_url(source: dict) -> dict[str, str]:
    return {
        record["source_url"]: record["text_snippet"]
        for record in source["evidence_context"]["records"]
        if record.get("fetch_status") == "ok" and record.get("text_snippet")
    }


def validate_reviews(
    review_path: Path,
    worklist_path: Path,
    expected_reviewer_id: str,
) -> list[dict]:
    worklist = list(iter_jsonl(worklist_path))
    reviews = list(iter_jsonl(review_path))
    if len(reviews) != len(worklist):
        raise ValueError(f"review row count mismatch in {review_path}")
    stripped = []
    for index, (review, source) in enumerate(zip(reviews, worklist), start=1):
        if set(review) != REVIEW_KEYS:
            raise ValueError(f"review schema mismatch at {review_path}:{index}")
        if review["reviewer_id"] != expected_reviewer_id:
            raise ValueError(f"reviewer identity mismatch at {review_path}:{index}")
        if not isinstance(review["run_id"], str) or not review["run_id"].strip():
            raise ValueError(f"blank run_id at {review_path}:{index}")
        model_row = {key: review[key] for key in runner.ITEM_KEYS}
        runner.validate_model_row(model_row, source)
        stripped.append(model_row)
        rationale = review["rationale"]
        if not isinstance(rationale, str) or len(rationale.strip()) < 120:
            raise ValueError(f"rationale too short at {review_path}:{index}")
        citations = review["supporting_evidence"]
        if not isinstance(citations, list):
            raise ValueError(f"supporting_evidence is not a list at {review_path}:{index}")
        available = evidence_by_url(source)
        seen = set()
        for citation in citations:
            if not isinstance(citation, dict) or set(citation) != {"url", "quote"}:
                raise ValueError(f"citation schema mismatch at {review_path}:{index}")
            url, quote = citation["url"], citation["quote"]
            if url not in available:
                raise ValueError(f"citation URL is not successful frozen evidence at {review_path}:{index}")
            if not isinstance(quote, str) or not 20 <= len(quote) <= 280:
                raise ValueError(f"citation quote length invalid at {review_path}:{index}")
            if quote not in available[url]:
                raise ValueError(f"citation is not a literal frozen substring at {review_path}:{index}")
            marker = (url, quote)
            if marker in seen:
                raise ValueError(f"duplicate citation at {review_path}:{index}")
            seen.add(marker)
    runner.validate_model_rows(stripped, worklist)
    return reviews


def validate_requests(
    request_path: Path,
    reviews: list[dict],
    worklist_path: Path,
    manifest_path: Path,
    expected_reviewer_id: str,
    role: str,
    execution: dict,
) -> list[dict]:
    records = list(iter_jsonl(request_path))
    expected_ids = [row["review_id"] for row in reviews]
    actual_ids = []
    run_by_id = {}
    sessions = set()
    run_ids = set()
    for index, record in enumerate(records, start=1):
        if record.get("artifact_type") != "rq2_post_profile_cwe_all50_review_request_v3":
            raise ValueError(f"request artifact type mismatch at {request_path}:{index}")
        if record.get("request_index") != index:
            raise ValueError(f"request index mismatch at {request_path}:{index}")
        if record.get("reviewer_id") != expected_reviewer_id or record.get("role") != role:
            raise ValueError(f"request role/reviewer mismatch at {request_path}:{index}")
        if record.get("label_is_human") is not False:
            raise ValueError(f"request human-label boundary violated at {request_path}:{index}")
        if record.get("model") != execution["model"]:
            raise ValueError(f"request model mismatch at {request_path}:{index}")
        if record.get("reasoning_effort") != execution["reasoning_effort"]:
            raise ValueError(f"request reasoning mismatch at {request_path}:{index}")
        if record.get("execution_backend") != execution["backend"]:
            raise ValueError(f"request backend mismatch at {request_path}:{index}")
        if not str(record.get("execution_backend_version") or "").startswith("codex-cli "):
            raise ValueError(f"request backend version missing at {request_path}:{index}")
        for key, expected_path in (("manifest", manifest_path), ("worklist", worklist_path)):
            entry = record.get(key) or {}
            if entry.get("path") != str(expected_path) or entry.get("sha256") != sha256(expected_path):
                raise ValueError(f"request {key} binding mismatch at {request_path}:{index}")
        ids = record.get("review_ids") or []
        if record.get("row_count") != len(ids) or not 1 <= len(ids) <= execution["batch_size"]:
            raise ValueError(f"request row count mismatch at {request_path}:{index}")
        batch_rows = [row for row in reviews if row["review_id"] in set(ids)]
        if [row["review_id"] for row in batch_rows] != ids:
            raise ValueError(f"request/reviewer order mismatch at {request_path}:{index}")
        if canonical_sha256(batch_rows) != record.get("response_rows_sha256"):
            raise ValueError(f"request response hash mismatch at {request_path}:{index}")
        run_id = record.get("run_id")
        session = record.get("session_id")
        if not run_id or run_id in run_ids or not session or session in sessions:
            raise ValueError(f"request run/session identity reused at {request_path}:{index}")
        run_ids.add(run_id)
        sessions.add(session)
        for review_id in ids:
            run_by_id[review_id] = run_id
        actual_ids.extend(ids)
    if actual_ids != expected_ids:
        raise ValueError(f"request coverage/order differs from reviewer output: {request_path}")
    if any(row["run_id"] != run_by_id.get(row["review_id"]) for row in reviews):
        raise ValueError(f"reviewer run IDs differ from request log: {request_path}")
    return records


def strict_consensus(left: dict, right: dict) -> tuple[bool, str | None]:
    exact = all(left[key] == right[key] for key in STRICT_KEYS)
    strict = (
        exact
        and left["discrepancy_label"] != "uncertain"
        and left["confidence"] in {"high", "medium"}
        and right["confidence"] in {"high", "medium"}
        and not left["needs_additional_review"]
        and not right["needs_additional_review"]
    )
    return strict, left["discrepancy_label"] if strict else None


def render_markdown(summary: dict) -> str:
    lines = [
        "# Post-Profile CWE All-50 Evidence Diagnostic",
        "",
        "This is a post-hoc, field-complete, non-human development audit. It is not human gold or a confirmatory gain estimate.",
        "",
        f"- Strict evidence consensus: `{summary['strict_rows']}/{summary['rows']}`.",
        f"- Current agreement on strict rows: `{summary['current_agreement_strict']}/{summary['strict_rows']}`.",
        f"- CWE-candidate agreement on strict rows: `{summary['candidate_agreement_strict']}/{summary['strict_rows']}`.",
        f"- Hidden profile-difference rows strict/candidate direction: `{summary['difference_strict_rows']}/{summary['candidate_direction_strict_rows']}`.",
        "",
        "| CVE | Prior strict | Evidence E | Evidence F | Evidence strict | Direction |",
        "|---|---:|---|---|---:|---|",
    ]
    for row in summary["difference_rows"]:
        lines.append(
            f"| {row['cve_id']} | {str(row['prior_strict_consensus']).lower()} | "
            f"{row['reviewer_e_label']} | {row['reviewer_f_label']} | "
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
    reviewer_e_path = resolve(args.reviewer_e)
    reviewer_f_path = resolve(args.reviewer_f)
    requests_e_path = resolve(args.requests_e)
    requests_f_path = resolve(args.requests_f)
    output_dir = resolve(args.output_dir)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("artifact_type") != "rq2_post_profile_cwe_all50_evidence_manifest_v3":
        raise ValueError("unexpected all-50 manifest")
    if manifest.get("row_count") != 50:
        raise ValueError("all-50 manifest row count mismatch")
    selection = manifest.get("selection") or {}
    if not all(
        selection.get(key) is True
        for key in (
            "post_hoc_field_complete",
            "selected_after_a_b_unsealing",
            "all_cwe_rows_in_sealed_250_cohort",
            "profile_differences_hidden_from_reviewers",
        )
    ):
        raise ValueError("all-50 selection boundary drift")
    if selection.get("supersedes_failed_v1_fixed_subset_contract_attempt") is not True:
        raise ValueError("v3 does not bind the failed fixed-subset attempt")
    if selection.get("supersedes_failed_v2_literal_evidence_contract_attempt") is not True:
        raise ValueError("v3 does not bind the failed literal-evidence attempt")
    for entry in manifest["inputs"].values():
        path = Path(entry["path"])
        if not path.is_file() or sha256(path) != entry["sha256"]:
            raise ValueError(f"sealed input changed: {path}")
    if sha256(Path(manifest["builder"]["path"])) != manifest["builder"]["sha256"]:
        raise ValueError("builder changed after sealing")
    worklist_e = Path(manifest["worklists"]["reviewer_e"]["path"])
    worklist_f = Path(manifest["worklists"]["reviewer_f"]["path"])
    for key, path in (("reviewer_e", worklist_e), ("reviewer_f", worklist_f)):
        if sha256(path) != manifest["worklists"][key]["sha256"]:
            raise ValueError(f"sealed worklist changed: {key}")
    ids_e = [row["review_id"] for row in iter_jsonl(worklist_e)]
    ids_f = [row["review_id"] for row in iter_jsonl(worklist_f)]
    if ids_f != list(reversed(ids_e)):
        raise ValueError("reviewer F worklist is not the exact reverse")

    reviewer_id_e = "codex_post_profile_cwe_all50_v3_e"
    reviewer_id_f = "codex_post_profile_cwe_all50_v3_f"
    reviews_e = validate_reviews(reviewer_e_path, worklist_e, reviewer_id_e)
    reviews_f = validate_reviews(reviewer_f_path, worklist_f, reviewer_id_f)
    requests_e = validate_requests(
        requests_e_path,
        reviews_e,
        worklist_e,
        manifest_path,
        reviewer_id_e,
        "e",
        manifest["execution"],
    )
    requests_f = validate_requests(
        requests_f_path,
        reviews_f,
        worklist_f,
        manifest_path,
        reviewer_id_f,
        "f",
        manifest["execution"],
    )
    sessions_e = {row["session_id"] for row in requests_e}
    sessions_f = {row["session_id"] for row in requests_f}
    runs_e = {row["run_id"] for row in requests_e}
    runs_f = {row["run_id"] for row in requests_f}
    if sessions_e & sessions_f or runs_e & runs_f:
        raise ValueError("reviewer session/run sets are not disjoint")
    for path in (reviewer_e_path, reviewer_f_path, requests_e_path, requests_f_path):
        if path.stat().st_mtime_ns <= manifest["sealed_at_ns"]:
            raise ValueError(f"review artifact does not postdate seal: {path}")

    by_id_e = {row["review_id"]: row for row in reviews_e}
    by_id_f = {row["review_id"]: row for row in reviews_f}
    predictions = {
        row["sample_id"]: row
        for row in iter_jsonl(Path(manifest["inputs"]["predictions"]["path"]))
    }
    prior = {
        row["sample_id"]: row
        for row in iter_jsonl(Path(manifest["inputs"]["dual_consensus"]["path"]))
        if row.get("field") == "cwe_ids"
    }
    difference_ids = {
        row["sample_id"] for row in selection["profile_difference_rows"]
    }
    consensus_rows = []
    component_agreement = Counter()
    label_counts = Counter()
    for source in iter_jsonl(worklist_e):
        review_id = source["review_id"]
        left, right = by_id_e[review_id], by_id_f[review_id]
        for key in STRICT_KEYS:
            component_agreement[key] += int(left[key] == right[key])
        strict, label = strict_consensus(left, right)
        if label:
            label_counts[label] += 1
        sample_id = source["original_sample_id"]
        prediction = predictions[sample_id]
        if not strict:
            direction = "unresolved"
        elif prediction["current"] != prediction["cwe_taxonomy_v1"]:
            if label == prediction["cwe_taxonomy_v1"]:
                direction = "candidate"
            elif label == prediction["current"]:
                direction = "current"
            else:
                direction = "neither"
        else:
            direction = "profiles_equal_match" if label == prediction["current"] else "profiles_equal_mismatch"
        consensus_rows.append(
            {
                "review_id": review_id,
                "original_sample_id": sample_id,
                "cve_id": source["cve_id"],
                "field": "cwe_ids",
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "strict_consensus": strict,
                "consensus_label": label,
                "profile_difference": sample_id in difference_ids,
                "profile_direction": direction,
                "current_prediction": prediction["current"],
                "candidate_prediction": prediction["cwe_taxonomy_v1"],
                "prior_strict_consensus": prior[sample_id]["strict_consensus"],
                "prior_consensus_label": prior[sample_id]["consensus_label"],
                "reviewer_e": left,
                "reviewer_f": right,
            }
        )

    strict_rows = sum(row["strict_consensus"] for row in consensus_rows)
    current_agreement = sum(
        row["strict_consensus"] and row["consensus_label"] == row["current_prediction"]
        for row in consensus_rows
    )
    candidate_agreement = sum(
        row["strict_consensus"] and row["consensus_label"] == row["candidate_prediction"]
        for row in consensus_rows
    )
    difference_rows = [row for row in consensus_rows if row["profile_difference"]]
    difference_summary = [
        {
            "sample_id": row["original_sample_id"],
            "cve_id": row["cve_id"],
            "prior_strict_consensus": row["prior_strict_consensus"],
            "reviewer_e_label": row["reviewer_e"]["discrepancy_label"],
            "reviewer_f_label": row["reviewer_f"]["discrepancy_label"],
            "strict_consensus": row["strict_consensus"],
            "consensus_label": row["consensus_label"],
            "profile_direction": row["profile_direction"],
        }
        for row in difference_rows
    ]
    summary = {
        "artifact_type": "rq2_post_profile_cwe_all50_evidence_summary_v3",
        "rows": len(consensus_rows),
        "strict_rows": strict_rows,
        "strict_coverage": strict_rows / len(consensus_rows),
        "strict_label_counts": dict(sorted(label_counts.items())),
        "component_exact_agreement": {
            key: {"count": component_agreement[key], "rows": len(consensus_rows)}
            for key in STRICT_KEYS
        },
        "prior_strict_rows": sum(row["prior_strict_consensus"] for row in consensus_rows),
        "resolved_prior_non_strict_rows": sum(
            row["strict_consensus"] and not row["prior_strict_consensus"]
            for row in consensus_rows
        ),
        "current_agreement_strict": current_agreement,
        "candidate_agreement_strict": candidate_agreement,
        "profile_agreement_difference_strict": candidate_agreement - current_agreement,
        "difference_rows_total": len(difference_rows),
        "difference_strict_rows": sum(row["strict_consensus"] for row in difference_rows),
        "candidate_direction_strict_rows": sum(
            row["profile_direction"] == "candidate" for row in difference_rows
        ),
        "current_direction_strict_rows": sum(
            row["profile_direction"] == "current" for row in difference_rows
        ),
        "neither_direction_strict_rows": sum(
            row["profile_direction"] == "neither" for row in difference_rows
        ),
        "difference_unresolved_rows": sum(
            row["profile_direction"] == "unresolved" for row in difference_rows
        ),
        "difference_rows": difference_summary,
        "reviewer_e_requests": len(requests_e),
        "reviewer_f_requests": len(requests_f),
        "reviewer_sessions_disjoint": True,
        **manifest["selection"],
        **manifest["claim_boundary"],
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    consensus_path = output_dir / "dual_review_consensus.jsonl"
    summary_path = output_dir / "summary.json"
    summary_md_path = output_dir / "summary.md"
    merge_manifest_path = output_dir / "merge_manifest.json"
    for path in (consensus_path, summary_path, summary_md_path, merge_manifest_path):
        if path.exists():
            raise FileExistsError(f"refusing to overwrite merge output: {path}")
    write_jsonl(consensus_path, consensus_rows)
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    summary_md_path.write_text(render_markdown(summary), encoding="utf-8")
    merge_manifest = {
        "artifact_type": "rq2_post_profile_cwe_all50_merge_manifest_v3",
        "source_manifest": {"path": str(manifest_path), "sha256": sha256(manifest_path)},
        "inputs": {
            "reviewer_e": {"path": str(reviewer_e_path), "sha256": sha256(reviewer_e_path)},
            "reviewer_f": {"path": str(reviewer_f_path), "sha256": sha256(reviewer_f_path)},
            "requests_e": {"path": str(requests_e_path), "sha256": sha256(requests_e_path)},
            "requests_f": {"path": str(requests_f_path), "sha256": sha256(requests_f_path)},
        },
        "outputs": {
            "consensus": {"path": str(consensus_path), "sha256": sha256(consensus_path)},
            "summary": {"path": str(summary_path), "sha256": sha256(summary_path)},
            "summary_markdown": {"path": str(summary_md_path), "sha256": sha256(summary_md_path)},
        },
        "claim_boundary": manifest["claim_boundary"],
    }
    merge_manifest_path.write_text(
        json.dumps(merge_manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        "Merged post-profile CWE all-50 evidence review: "
        f"strict={strict_rows}/50 current={current_agreement} candidate={candidate_agreement} "
        f"difference_candidate={summary['candidate_direction_strict_rows']}/3"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
