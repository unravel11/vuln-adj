#!/usr/bin/env python3
"""Validate and merge two blind Codex reviews for the RQ2 typing holdout."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASE = "data/annotations/holdout/rq2_typing_v1"
DEFAULT_OUTPUT_DIR = "results/holdout/rq2_typing_v1"
LABELS = {
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
    "uncertain",
}
CONFIDENCE = {"high", "medium", "low"}
VERSION_REASONING = {
    "token_support",
    "range_semantic",
    "package_identity",
    "insufficient_evidence",
    "not_applicable",
}
OUTPUT_KEYS = {
    "schema_version",
    "candidate_status",
    "label_is_human",
    "annotator_type",
    "annotator_id",
    "model",
    "api_route",
    "execution_backend",
    "execution_backend_version",
    "execution_backend_sha256",
    "execution_reasoning_effort",
    "execution_max_output_tokens",
    "execution_session_id",
    "execution_usage",
    "schedule",
    "rq2_contract_mode",
    "pass_id",
    "generated_at",
    "prompt_path",
    "prompt_sha256",
    "input_path",
    "input_sha256",
    "binding_manifest_path",
    "binding_manifest_sha256",
    "sample_id",
    "original_sample_id",
    "baseline_status",
    "contract_normalizations",
    "annotation",
}
ANNOTATION_KEYS = {
    "sample_id",
    "cve_id",
    "field",
    "discrepancy_label",
    "adjudicated_source",
    "adjudicated_value",
    "evidence_urls",
    "rationale",
    "evidence_notes",
    "uncertainty_notes",
    "version_reasoning_type",
    "confidence",
    "needs_human_review",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-dir", default=DEFAULT_BASE)
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


def load_unique(path: Path, key: str = "sample_id") -> dict[str, dict]:
    result = {}
    for row in iter_jsonl(path):
        value = row.get(key)
        if not value or value in result:
            raise ValueError(f"{path}: missing or duplicate {key}={value}")
        result[value] = row
    return result


def parse_time(value: object) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    try:
        datetime.fromisoformat(text.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def cohen_kappa(left: list[str], right: list[str]) -> float | None:
    if len(left) != len(right):
        raise ValueError("kappa inputs have different lengths")
    if not left:
        return None
    observed = sum(a == b for a, b in zip(left, right)) / len(left)
    left_counts = Counter(left)
    right_counts = Counter(right)
    labels = set(left) | set(right)
    expected = sum(
        left_counts[label] / len(left) * right_counts[label] / len(right)
        for label in labels
    )
    return None if expected == 1 else (observed - expected) / (1 - expected)


def allowed_urls(blind: dict) -> set[str]:
    context = blind.get("reference_context") or {}
    return {
        str(url)
        for key in ("nvd_urls", "ghsa_urls")
        for url in context.get(key) or []
        if url
    }


def validate_review(
    record: dict,
    blind: dict,
    *,
    expected_pass_id: str,
    expected_input_path: Path,
    expected_prompt_path: Path,
    expected_manifest_path: Path,
    expected_manifest_sha256: str,
    expected_execution: dict,
) -> dict:
    sample_id = blind["sample_id"]
    if set(record) != OUTPUT_KEYS:
        raise ValueError(
            f"{sample_id}: reviewer output keys differ; "
            f"missing={sorted(OUTPUT_KEYS - set(record))}, "
            f"extra={sorted(set(record) - OUTPUT_KEYS)}"
        )
    if record["schema_version"] != "expert_candidate_v1":
        raise ValueError(f"{sample_id}: invalid reviewer schema_version")
    if record["candidate_status"] != "unreviewed":
        raise ValueError(f"{sample_id}: reviewer candidate_status drift")
    if record["label_is_human"] is not False:
        raise ValueError(f"{sample_id}: reviewer output must remain non-human")
    if record["annotator_type"] != "ai_security_expert":
        raise ValueError(f"{sample_id}: invalid annotator_type")
    if record["model"] != expected_execution["model"]:
        raise ValueError(f"{sample_id}: unexpected reviewer model")
    if record["api_route"] != expected_execution["api_route"]:
        raise ValueError(f"{sample_id}: reviewer API route mismatch")
    if record["execution_backend"] != expected_execution["backend"]:
        raise ValueError(f"{sample_id}: reviewer execution backend mismatch")
    if record["execution_backend_version"] != expected_execution["version"]:
        raise ValueError(f"{sample_id}: reviewer backend version mismatch")
    if record["execution_backend_sha256"] != expected_execution["sha256"]:
        raise ValueError(f"{sample_id}: reviewer backend hash mismatch")
    if record["execution_reasoning_effort"] != expected_execution["reasoning_effort"]:
        raise ValueError(f"{sample_id}: reviewer reasoning effort mismatch")
    if record["execution_max_output_tokens"] != expected_execution["max_output_tokens"]:
        raise ValueError(f"{sample_id}: reviewer output-token cap mismatch")
    if not str(record["execution_session_id"] or "").strip():
        raise ValueError(f"{sample_id}: reviewer lacks a Codex session id")
    usage = record["execution_usage"]
    if not isinstance(usage, dict):
        raise ValueError(f"{sample_id}: reviewer execution_usage must be an object")
    for key in ("input_tokens", "output_tokens"):
        if not isinstance(usage.get(key), int) or usage[key] < 0:
            raise ValueError(f"{sample_id}: invalid reviewer usage.{key}")
    if record["pass_id"] != expected_pass_id:
        raise ValueError(f"{sample_id}: reviewer pass_id mismatch")
    if record["rq2_contract_mode"] != "strict":
        raise ValueError(f"{sample_id}: reviewer did not use strict RQ2 mode")
    if record["schedule"] != "input":
        raise ValueError(f"{sample_id}: reviewer did not preserve sealed input order")
    if Path(record["input_path"]) != expected_input_path:
        raise ValueError(f"{sample_id}: reviewer input_path mismatch")
    if record["input_sha256"] != sha256(expected_input_path):
        raise ValueError(f"{sample_id}: reviewer input_sha256 mismatch")
    if Path(record["prompt_path"]) != expected_prompt_path:
        raise ValueError(f"{sample_id}: reviewer prompt_path mismatch")
    if record["prompt_sha256"] != sha256(expected_prompt_path):
        raise ValueError(f"{sample_id}: reviewer prompt_sha256 mismatch")
    if Path(record["binding_manifest_path"]) != expected_manifest_path:
        raise ValueError(f"{sample_id}: reviewer binding_manifest_path mismatch")
    if record["binding_manifest_sha256"] != expected_manifest_sha256:
        raise ValueError(f"{sample_id}: reviewer binding_manifest_sha256 mismatch")
    if record["sample_id"] != sample_id:
        raise ValueError(f"{sample_id}: reviewer sample_id mismatch")
    if record["original_sample_id"] is not None:
        raise ValueError(f"{sample_id}: unexpected original_sample_id")
    if record["baseline_status"] is not None:
        raise ValueError(f"{sample_id}: reviewer output leaked baseline_status")
    if record["contract_normalizations"] != []:
        raise ValueError(f"{sample_id}: strict reviewer output was mechanically rewritten")
    if not parse_time(record["generated_at"]):
        raise ValueError(f"{sample_id}: invalid generated_at")

    annotation = record["annotation"]
    if not isinstance(annotation, dict) or set(annotation) != ANNOTATION_KEYS:
        raise ValueError(f"{sample_id}: invalid annotation keys")
    if annotation["sample_id"] != sample_id:
        raise ValueError(f"{sample_id}: annotation sample_id mismatch")
    if annotation["cve_id"] != blind["cve_id"] or annotation["field"] != blind["field"]:
        raise ValueError(f"{sample_id}: annotation identity mismatch")
    if annotation["discrepancy_label"] not in LABELS:
        raise ValueError(f"{sample_id}: invalid discrepancy label")
    if annotation["confidence"] not in CONFIDENCE:
        raise ValueError(f"{sample_id}: invalid confidence")
    if annotation["adjudicated_source"] != "abstain":
        raise ValueError(f"{sample_id}: RQ2 reviewer must abstain from source selection")
    if str(annotation["adjudicated_value"] or "").strip():
        raise ValueError(f"{sample_id}: RQ2 adjudicated_value must be blank")
    urls = annotation["evidence_urls"]
    if not isinstance(urls, list) or any(not isinstance(url, str) for url in urls):
        raise ValueError(f"{sample_id}: evidence_urls must be a string list")
    if len(urls) != len(set(urls)) or set(urls) - allowed_urls(blind):
        raise ValueError(f"{sample_id}: evidence_urls are duplicate or unavailable")
    if len(str(annotation["rationale"] or "").strip()) < 40:
        raise ValueError(f"{sample_id}: rationale must contain at least 40 characters")
    if annotation["version_reasoning_type"] not in VERSION_REASONING:
        raise ValueError(f"{sample_id}: invalid version_reasoning_type")
    if blind["field"] != "affected_versions" and annotation["version_reasoning_type"] != "not_applicable":
        raise ValueError(f"{sample_id}: non-version field has version reasoning")
    if blind["field"] == "affected_versions" and annotation["version_reasoning_type"] == "not_applicable":
        raise ValueError(f"{sample_id}: affected_versions requires version reasoning")
    if (
        annotation["discrepancy_label"] == "uncertain"
        or annotation["confidence"] == "low"
    ) and annotation["needs_human_review"] is not True:
        raise ValueError(f"{sample_id}: uncertain/low-confidence row must request review")
    if not isinstance(annotation["needs_human_review"], bool):
        raise ValueError(f"{sample_id}: needs_human_review must be boolean")
    return annotation


def is_strict_consensus(left: dict, right: dict) -> bool:
    return (
        left["discrepancy_label"] == right["discrepancy_label"]
        and left["discrepancy_label"] != "uncertain"
        and left["confidence"] != "low"
        and right["confidence"] != "low"
        and left["needs_human_review"] is False
        and right["needs_human_review"] is False
    )


def verify_manifest(manifest: dict, manifest_path: Path) -> None:
    if manifest.get("artifact_type") != "rq2_typing_holdout_v1_manifest":
        raise ValueError("unexpected holdout manifest artifact_type")
    if manifest.get("label_is_human") is not False:
        raise ValueError("holdout manifest must remain non-human")
    if manifest.get("selected_rows") != 1250 or manifest.get("rows_per_field") != 250:
        raise ValueError("holdout manifest does not contain 250 rows per field")
    if manifest.get("candidate_profile_comparison_identifiable") is not False:
        raise ValueError("holdout incorrectly claims candidate profile identifiability")
    for section in ("inputs", "outputs"):
        for name, item in manifest.get(section, {}).items():
            path = Path(item["path"])
            if sha256(path) != item["sha256"]:
                raise ValueError(f"manifest hash mismatch for {section}.{name}: {path}")
    if manifest_path.stat().st_mtime_ns < manifest["sealed_at_ns"]:
        raise ValueError("manifest timestamp precedes its sealed_at_ns")


def render_markdown(summary: dict) -> str:
    return "\n".join(
        [
            "# RQ2 Typing Holdout Dual-Codex Review",
            "",
            "> Prediction-sealed, development-CVE-disjoint, non-human diagnostic.",
            "",
            f"- Rows: `{summary['rows']}`",
            f"- Unique CVEs: `{summary['unique_cves']}`",
            f"- Exact label agreement: `{summary['exact_label_agreement']}/{summary['rows']}` (`{summary['exact_label_agreement_rate']:.4f}`)",
            f"- Cohen's kappa: `{summary['cohen_kappa']}`",
            f"- Strict consensus: `{summary['strict_consensus_rows']}/{summary['rows']}` (`{summary['strict_consensus_coverage']:.4f}`)",
            "",
            "Strict consensus excludes uncertain labels, low confidence, and either reviewer's additional-review request.",
            "",
        ]
    )


def main() -> int:
    args = parse_args()
    base_dir = resolve(args.base_dir)
    output_dir = resolve(args.output_dir)
    manifest_path = base_dir / "manifest.sealed.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    verify_manifest(manifest, manifest_path)
    source_path = Path(manifest["outputs"]["source_rows"]["path"])
    blind_a_path = Path(manifest["outputs"]["blind_worklist_a"]["path"])
    blind_b_path = Path(manifest["outputs"]["blind_worklist_b"]["path"])
    prompt_path = Path(manifest["inputs"]["prompt"]["path"])
    execution_contract = manifest["review_protocol"]["execution_contract"]
    reviewer_a_path = Path(manifest["review_protocol"]["reviewer_a_output"])
    reviewer_b_path = Path(manifest["review_protocol"]["reviewer_b_output"])
    for path in (reviewer_a_path, reviewer_b_path):
        if not path.exists():
            raise FileNotFoundError(path)
        if path.stat().st_mtime_ns <= manifest["sealed_at_ns"]:
            raise ValueError(f"reviewer output predates the holdout seal: {path}")
    if reviewer_a_path == reviewer_b_path or sha256(reviewer_a_path) == sha256(reviewer_b_path):
        raise ValueError("reviewer outputs must be distinct files with distinct content")

    source_rows = load_unique(source_path)
    blind_a = load_unique(blind_a_path)
    blind_b = load_unique(blind_b_path)
    review_a = load_unique(reviewer_a_path)
    review_b = load_unique(reviewer_b_path)
    sample_ids = list(source_rows)
    if not all(set(rows) == set(sample_ids) for rows in (blind_a, blind_b, review_a, review_b)):
        raise ValueError("source/blind/reviewer sample-id sets differ")
    if list(blind_a) != sample_ids or list(blind_b) != list(reversed(sample_ids)):
        raise ValueError("sealed reviewer worklist orders changed")

    merged = []
    labels_a = []
    labels_b = []
    for sample_id in sample_ids:
        source = source_rows[sample_id]
        if source["cve_id"] != blind_a[sample_id]["cve_id"] or blind_a[sample_id] != blind_b[sample_id]:
            raise ValueError(f"{sample_id}: source/blind identity drift")
        left = validate_review(
            review_a[sample_id],
            blind_a[sample_id],
            expected_pass_id=manifest["review_protocol"]["reviewer_a_pass_id"],
            expected_input_path=blind_a_path,
            expected_prompt_path=prompt_path,
            expected_manifest_path=manifest_path,
            expected_manifest_sha256=sha256(manifest_path),
            expected_execution=execution_contract,
        )
        right = validate_review(
            review_b[sample_id],
            blind_b[sample_id],
            expected_pass_id=manifest["review_protocol"]["reviewer_b_pass_id"],
            expected_input_path=blind_b_path,
            expected_prompt_path=prompt_path,
            expected_manifest_path=manifest_path,
            expected_manifest_sha256=sha256(manifest_path),
            expected_execution=execution_contract,
        )
        strict = is_strict_consensus(left, right)
        labels_a.append(left["discrepancy_label"])
        labels_b.append(right["discrepancy_label"])
        merged.append(
            {
                "sample_id": sample_id,
                "cve_id": source["cve_id"],
                "field": source["field"],
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "strict_consensus": strict,
                "consensus_label": left["discrepancy_label"] if strict else None,
                "reviewer_a": left,
                "reviewer_b": right,
            }
        )

    sessions_a = {
        row["execution_session_id"] for row in review_a.values()
    }
    sessions_b = {
        row["execution_session_id"] for row in review_b.values()
    }
    if sessions_a & sessions_b:
        raise ValueError("reviewer A/B Codex session IDs must be disjoint")

    exact = sum(left == right for left, right in zip(labels_a, labels_b))
    strict_rows = [row for row in merged if row["strict_consensus"]]
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
    kappa = cohen_kappa(labels_a, labels_b)
    summary = {
        "artifact_type": "rq2_typing_holdout_dual_codex_review",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "rows": len(merged),
        "unique_cves": len({row["cve_id"] for row in merged}),
        "reviewer_a_label_counts": dict(sorted(Counter(labels_a).items())),
        "reviewer_b_label_counts": dict(sorted(Counter(labels_b).items())),
        "exact_label_agreement": exact,
        "exact_label_agreement_rate": exact / len(merged),
        "cohen_kappa": kappa,
        "strict_consensus_rows": len(strict_rows),
        "strict_consensus_coverage": len(strict_rows) / len(merged),
        "strict_label_counts": dict(
            sorted(Counter(row["consensus_label"] for row in strict_rows).items())
        ),
        "per_field": per_field,
        "reviewer_files": {
            "a": {"path": str(reviewer_a_path), "sha256": sha256(reviewer_a_path)},
            "b": {"path": str(reviewer_b_path), "sha256": sha256(reviewer_b_path)},
        },
        "source_manifest": {"path": str(manifest_path), "sha256": sha256(manifest_path)},
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    merged_path = output_dir / "dual_review_consensus.jsonl"
    summary_path = output_dir / "dual_review_summary.json"
    markdown_path = output_dir / "dual_review_summary.md"
    merge_manifest_path = output_dir / "merge_manifest.json"
    write_jsonl(merged_path, merged)
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render_markdown(summary), encoding="utf-8")
    merge_manifest = {
        "artifact_type": "rq2_typing_holdout_merge_manifest",
        "label_is_human": False,
        "inputs": {
            "sealed_manifest": {"path": str(manifest_path), "sha256": sha256(manifest_path)},
            "reviewer_a": {"path": str(reviewer_a_path), "sha256": sha256(reviewer_a_path)},
            "reviewer_b": {"path": str(reviewer_b_path), "sha256": sha256(reviewer_b_path)},
        },
        "outputs": {
            "consensus": {"path": str(merged_path), "sha256": sha256(merged_path)},
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
