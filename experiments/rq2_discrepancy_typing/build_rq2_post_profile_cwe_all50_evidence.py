#!/usr/bin/env python3
"""Seal frozen evidence worklists for all 50 post-profile CWE rows."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from scripts.build_rq3_evidence_samples import FetchConfig, load_or_fetch  # noqa: E402
from analyze_cwe_taxonomy_variants import CweCatalog, relation_profile  # noqa: E402
from build_rq2_post_profile_cwe_evidence_secondary import (  # noqa: E402
    collect_references,
    derive_fetch_url,
    recursive_keys,
)


BASE = "data/annotations/holdout/rq2_post_profile_snapshot_v1"
RESULT_BASE = "results/holdout/rq2_post_profile_snapshot_v1/review"
DEFAULT_SOURCE = f"{BASE}/source_rows.jsonl"
DEFAULT_PREDICTIONS = f"{BASE}/predictions.sealed.jsonl"
DEFAULT_SEAL = f"{BASE}/manifest.sealed.json"
DEFAULT_A = f"{BASE}/reviewer_a.jsonl"
DEFAULT_B = f"{BASE}/reviewer_b.jsonl"
DEFAULT_CONSENSUS = f"{RESULT_BASE}/dual_review_consensus.jsonl"
DEFAULT_EVALUATION = f"{RESULT_BASE}/profile_evaluation.json"
DEFAULT_CWE_ZIP = "data/external/cwe/cwec_v4.20.xml.zip"
DEFAULT_PROMPT = "docs/prompts/rq2_post_profile_cwe_all50_evidence_review_v3.md"
DEFAULT_CONTRACT = (
    "docs/annotation_guidelines/rq2_post_profile_cwe_all50_evidence_contract_v3.md"
)
# V2 intentionally reuses the already frozen v1 URL cache. No refresh is used
# in the authoritative run, so response content does not drift between attempts.
DEFAULT_OUTPUT_DIR = f"{BASE}/cwe_all50_evidence_v3"
DEFAULT_CACHE_DIR = "data/evidence_cache/rq2/post_profile_cwe_all50_evidence_v1/url_cache"
DEFAULT_FAILED_V1_ARCHIVE = (
    f"{BASE}/cwe_all50_evidence_v1_failed_fixed_subset_contract_attempt.tar.gz"
)
DEFAULT_FAILED_V2_ARCHIVE = (
    f"{BASE}/cwe_all50_evidence_v2_failed_literal_evidence_contract_attempt.tar.gz"
)
EXPECTED_ROWS = 50
MAX_REFERENCES = 3
MAX_BYTES = 1_500_000
MAX_TEXT_CHARS = 6_000
FORBIDDEN_KEYS = {
    "annotation",
    "candidate",
    "consensus_label",
    "current",
    "current_prediction",
    "cwe_taxonomy_v1",
    "gold_label",
    "label_is_human",
    "profile_difference",
    "profile_prediction",
    "reviewer_a",
    "reviewer_b",
    "strict_consensus",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-rows", default=DEFAULT_SOURCE)
    parser.add_argument("--predictions", default=DEFAULT_PREDICTIONS)
    parser.add_argument("--cohort-manifest", default=DEFAULT_SEAL)
    parser.add_argument("--reviewer-a", default=DEFAULT_A)
    parser.add_argument("--reviewer-b", default=DEFAULT_B)
    parser.add_argument("--dual-consensus", default=DEFAULT_CONSENSUS)
    parser.add_argument("--profile-evaluation", default=DEFAULT_EVALUATION)
    parser.add_argument("--cwe-xml-zip", default=DEFAULT_CWE_ZIP)
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR)
    parser.add_argument("--timeout-seconds", type=int, default=25)
    parser.add_argument("--max-text-chars", type=int, default=MAX_TEXT_CHARS)
    parser.add_argument("--refresh", action="store_true")
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


def set_relation(category: str) -> str:
    if category == "exact_set":
        return "exact_set"
    if category == "literal_strict_subset":
        return "literal_strict_subset"
    if category.startswith("overlap_"):
        return "overlap_non_subset"
    if category.startswith("disjoint_"):
        return "disjoint"
    raise ValueError(f"unknown CWE relation category: {category}")


def cwe_rows(rows: list[dict]) -> list[dict]:
    selected = [row for row in rows if row.get("field") == "cwe_ids"]
    if len(selected) != EXPECTED_ROWS:
        raise ValueError(f"expected {EXPECTED_ROWS} CWE rows, found {len(selected)}")
    ids = [row.get("sample_id") for row in selected]
    if len(set(ids)) != EXPECTED_ROWS:
        raise ValueError("CWE source sample IDs are not unique")
    return selected


def build_row(
    index: int,
    source: dict,
    catalog: CweCatalog,
    cache_dir: Path,
    fetch_config: FetchConfig,
) -> tuple[dict, Counter]:
    profile = relation_profile(source["nvd_value"], source["ghsa_value"], catalog)
    relation = set_relation(profile["category"])
    counts = Counter()
    evidence = []
    for reference in collect_references(source)[:MAX_REFERENCES]:
        fetch_url = derive_fetch_url(reference["source_url"])
        fetched, _ = load_or_fetch(fetch_url, cache_dir, fetch_config)
        status = fetched.get("fetch_status", "unknown")
        counts[status] += 1
        evidence.append(
            {
                **reference,
                "fetch_url": fetch_url,
                "host": fetched.get("host"),
                "title": fetched.get("title"),
                "published": fetched.get("published"),
                "fetch_status": status,
                "fetch_detail": fetched.get("fetch_detail"),
                "fetched_at": fetched.get("fetched_at"),
                "text_snippet": fetched.get("text_snippet") or "",
            }
        )
    row = {
        "review_id": f"rq2_post_profile_cwe_all50_v3:{index:03d}",
        "original_sample_id": source["sample_id"],
        "cve_id": source["cve_id"],
        "field": "cwe_ids",
        "nvd_value": source["nvd_value"],
        "ghsa_value": source["ghsa_value"],
        "deterministic_set_relation": relation,
        "official_taxonomy": {
            "source": source["field_context"]["taxonomy_source"],
            "entries": source["field_context"]["official_cwe_entries"],
            "relation_profile": profile,
        },
        "allowed_cwe_path_strings": [
            ">".join(item["cwe_id"] for item in path["path"])
            for path in profile["ancestor_descendant_paths"]
        ],
        "vulnerability_context": source["field_context"]["vulnerability_context"],
        "evidence_context": {
            "selection": "up_to_3_ranked_urls_from_frozen_nvd_or_ghsa_references",
            "records": evidence,
        },
        "review_contract": {
            "set_relation": [
                "exact_set",
                "literal_strict_subset",
                "overlap_non_subset",
                "disjoint",
            ],
            "discrepancy_label": [
                "equivalent",
                "incomplete",
                "representation_discrepancy",
                "factual_conflict",
                "uncertain",
            ],
            "taxonomy_compatibility": [
                "not_needed",
                "full",
                "partial",
                "none",
                "insufficient",
            ],
            "specific_mapping_verdict": [
                "same_mechanism_or_not_needed",
                "materially_different_or_contradicted",
                "insufficient",
            ],
            "confidence": ["high", "medium", "low"],
        },
    }
    leaked = recursive_keys(row) & FORBIDDEN_KEYS
    if leaked:
        raise ValueError(f"blind row leaks forbidden keys: {sorted(leaked)}")
    return row, counts


def main() -> int:
    args = parse_args()
    paths = {
        "source_rows": resolve(args.source_rows),
        "predictions": resolve(args.predictions),
        "cohort_manifest": resolve(args.cohort_manifest),
        "reviewer_a": resolve(args.reviewer_a),
        "reviewer_b": resolve(args.reviewer_b),
        "dual_consensus": resolve(args.dual_consensus),
        "profile_evaluation": resolve(args.profile_evaluation),
        "cwe_xml_zip": resolve(args.cwe_xml_zip),
        "prompt": resolve(args.prompt),
        "contract": resolve(args.contract),
        "failed_v1_archive": resolve(DEFAULT_FAILED_V1_ARCHIVE),
        "failed_v2_archive": resolve(DEFAULT_FAILED_V2_ARCHIVE),
        "fetcher_code": resolve("scripts/build_rq3_evidence_samples.py"),
        "taxonomy_code": resolve(
            "experiments/rq2_discrepancy_typing/analyze_cwe_taxonomy_variants.py"
        ),
        "helper_code": resolve(
            "experiments/rq2_discrepancy_typing/"
            "build_rq2_post_profile_cwe_evidence_secondary.py"
        ),
        "runner_code": resolve(
            "experiments/rq2_discrepancy_typing/"
            "run_rq2_post_profile_cwe_all50_review.py"
        ),
        "merge_code": resolve(
            "experiments/rq2_discrepancy_typing/merge_rq2_post_profile_cwe_all50.py"
        ),
        "verifier_code": resolve(
            "experiments/rq2_discrepancy_typing/verify_rq2_post_profile_cwe_all50.py"
        ),
    }
    for name, path in paths.items():
        if not path.is_file():
            raise FileNotFoundError(f"missing {name}: {path}")
    output_dir = resolve(args.output_dir)
    worklist_e = output_dir / "worklist_e.blind.jsonl"
    worklist_f = output_dir / "worklist_f.blind.jsonl"
    manifest_path = output_dir / "manifest.sealed.json"
    reviewer_outputs = {
        "reviewer_e": output_dir / "reviewer_e.jsonl",
        "reviewer_f": output_dir / "reviewer_f.jsonl",
        "requests_e": output_dir / "reviewer_e.requests.jsonl",
        "requests_f": output_dir / "reviewer_f.requests.jsonl",
    }
    existing = [
        str(path)
        for path in (worklist_e, worklist_f, manifest_path, *reviewer_outputs.values())
        if path.exists()
    ]
    if existing:
        raise ValueError(f"refusing to overwrite sealed/reviewer artifacts: {existing}")

    input_hashes = {name: sha256(path) for name, path in paths.items()}
    source_rows = cwe_rows(list(iter_jsonl(paths["source_rows"])))
    predictions = {
        row["sample_id"]: row for row in iter_jsonl(paths["predictions"])
    }
    if any(row["sample_id"] not in predictions for row in source_rows):
        raise ValueError("a CWE source row is absent from sealed predictions")
    profile_differences = [
        {
            "sample_id": row["sample_id"],
            "cve_id": row["cve_id"],
            "current": predictions[row["sample_id"]]["current"],
            "candidate": predictions[row["sample_id"]]["cwe_taxonomy_v1"],
        }
        for row in source_rows
        if predictions[row["sample_id"]]["current"]
        != predictions[row["sample_id"]]["cwe_taxonomy_v1"]
    ]
    if len(profile_differences) != 3:
        raise ValueError("expected exactly three hidden CWE profile differences")

    catalog = CweCatalog(paths["cwe_xml_zip"])
    cache_dir = resolve(args.cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    fetch_config = FetchConfig(
        timeout_seconds=args.timeout_seconds,
        max_bytes=MAX_BYTES,
        max_text_chars=args.max_text_chars,
        sleep_seconds=0.2,
        refresh=args.refresh,
    )
    blind_rows = []
    status_counts = Counter()
    relation_counts = Counter()
    for index, source in enumerate(source_rows, start=1):
        row, counts = build_row(index, source, catalog, cache_dir, fetch_config)
        blind_rows.append(row)
        status_counts.update(counts)
        relation_counts[row["deterministic_set_relation"]] += 1

    for name, path in paths.items():
        if sha256(path) != input_hashes[name]:
            raise ValueError(f"input changed during build: {name}")
    output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(worklist_e, blind_rows)
    write_jsonl(worklist_f, list(reversed(blind_rows)))
    manifest = {
        "artifact_type": "rq2_post_profile_cwe_all50_evidence_manifest_v3",
        "sealed_at_ns": time.time_ns(),
        "row_count": EXPECTED_ROWS,
        "selection": {
            "post_hoc_field_complete": True,
            "selected_after_a_b_unsealing": True,
            "all_cwe_rows_in_sealed_250_cohort": True,
            "profile_differences_hidden_from_reviewers": True,
            "source_profile_comparison": "cwe_taxonomy_v1",
            "profile_difference_rows": profile_differences,
            "supersedes_failed_v1_fixed_subset_contract_attempt": True,
            "supersedes_failed_v2_literal_evidence_contract_attempt": True,
        },
        "claim_boundary": {
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
            "eligible_for_confirmatory_method_gain_claim": False,
            "strict_event_time_claim_allowed": False,
            "candidate_promotion_allowed": False,
            "production_default_changed": False,
            "sealed_250_row_evaluation_changed": False,
        },
        "reviewer_outputs_absent_at_seal": True,
        "execution": {
            "backend": "codex-cli",
            "model": "gpt-5.5",
            "reasoning_effort": "medium",
            "batch_size": 5,
            "schedule": "input",
            "ephemeral_session_per_batch": True,
        },
        "set_relation_counts": dict(sorted(relation_counts.items())),
        "evidence_status_counts": dict(sorted(status_counts.items())),
        "inputs": {
            name: {"path": str(path), "sha256": input_hashes[name]}
            for name, path in paths.items()
        },
        "worklists": {
            "reviewer_e": {
                "path": str(worklist_e),
                "sha256": sha256(worklist_e),
                "order": "sealed_source_order",
                "reasoning_order": "set_then_taxonomy_then_mechanism",
            },
            "reviewer_f": {
                "path": str(worklist_f),
                "sha256": sha256(worklist_f),
                "order": "reverse_sealed_source_order",
                "reasoning_order": "mechanism_then_taxonomy_then_set",
            },
        },
        "reviewer_outputs": {
            name: str(path) for name, path in reviewer_outputs.items()
        },
        "builder": {"path": str(Path(__file__)), "sha256": sha256(Path(__file__))},
        "cautions": [
            "All 50 CWE rows were selected after original A/B and profile unsealing.",
            "Both reviewers are non-human Codex runs from one model family.",
            "The result cannot replace the sealed 250-row evaluation or estimate unbiased gain.",
        ],
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {worklist_e}")
    print(f"Wrote {worklist_f}")
    print(f"Wrote {manifest_path}")
    print(json.dumps(manifest["evidence_status_counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
