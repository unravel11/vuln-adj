#!/usr/bin/env python3
"""Build the v3 sealed evidence-secondary worklist for post-profile CWE rows."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from scripts.build_rq3_evidence_samples import FetchConfig, load_or_fetch  # noqa: E402
from analyze_cwe_taxonomy_variants import CweCatalog, relation_profile  # noqa: E402


DEFAULT_SOURCE_ROWS = (
    "data/annotations/holdout/rq2_post_profile_snapshot_v1/source_rows.jsonl"
)
DEFAULT_PREDICTIONS = (
    "data/annotations/holdout/rq2_post_profile_snapshot_v1/predictions.sealed.jsonl"
)
DEFAULT_COHORT_MANIFEST = (
    "data/annotations/holdout/rq2_post_profile_snapshot_v1/manifest.sealed.json"
)
DEFAULT_REVIEWER_A = (
    "data/annotations/holdout/rq2_post_profile_snapshot_v1/reviewer_a.jsonl"
)
DEFAULT_REVIEWER_B = (
    "data/annotations/holdout/rq2_post_profile_snapshot_v1/reviewer_b.jsonl"
)
DEFAULT_DUAL_CONSENSUS = (
    "results/holdout/rq2_post_profile_snapshot_v1/review/"
    "dual_review_consensus.jsonl"
)
DEFAULT_PROFILE_EVALUATION = (
    "results/holdout/rq2_post_profile_snapshot_v1/review/profile_evaluation.json"
)
DEFAULT_CWE_ZIP = "data/external/cwe/cwec_v4.20.xml.zip"
DEFAULT_PROMPT = (
    "docs/prompts/rq2_post_profile_cwe_evidence_secondary_review_v3.md"
)
DEFAULT_CONTRACT = (
    "docs/annotation_guidelines/"
    "rq2_post_profile_cwe_evidence_secondary_contract_v3.md"
)
DEFAULT_OUTPUT_DIR = (
    "data/annotations/holdout/rq2_post_profile_snapshot_v1/"
    "cwe_evidence_secondary_v3"
)
DEFAULT_CACHE_DIR = (
    "data/evidence_cache/rq2/post_profile_cwe_evidence_secondary_v3/url_cache"
)
DEFAULT_FAILED_V1_ARCHIVE = (
    "data/annotations/holdout/rq2_post_profile_snapshot_v1/"
    "cwe_evidence_secondary_v1_failed_contract_attempt.tar.gz"
)
DEFAULT_FAILED_V2_ARCHIVE = (
    "data/annotations/holdout/rq2_post_profile_snapshot_v1/"
    "cwe_evidence_secondary_v2_failed_path_contract_attempt.tar.gz"
)
DEFAULT_REVIEWER_C = f"{DEFAULT_OUTPUT_DIR}/reviewer_c.jsonl"
DEFAULT_REVIEWER_D = f"{DEFAULT_OUTPUT_DIR}/reviewer_d.jsonl"
DEFAULT_REQUESTS_C = f"{DEFAULT_OUTPUT_DIR}/reviewer_c.requests.jsonl"
DEFAULT_REQUESTS_D = f"{DEFAULT_OUTPUT_DIR}/reviewer_d.requests.jsonl"
DEFAULT_TIMEOUT_SECONDS = 25
DEFAULT_MAX_BYTES = 1_500_000
DEFAULT_MAX_TEXT_CHARS = 6_000
MAX_REFERENCES_PER_ROW = 5
TARGET_COUNT = 3
FORBIDDEN_BLIND_KEYS = {
    "annotation",
    "candidate",
    "consensus_label",
    "current",
    "current_prediction",
    "cwe_taxonomy_v1",
    "gold_label",
    "label_is_human",
    "profile_prediction",
    "reviewer_a",
    "reviewer_b",
    "strict_consensus",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-rows", default=DEFAULT_SOURCE_ROWS)
    parser.add_argument("--predictions", default=DEFAULT_PREDICTIONS)
    parser.add_argument("--cohort-manifest", default=DEFAULT_COHORT_MANIFEST)
    parser.add_argument("--reviewer-a", default=DEFAULT_REVIEWER_A)
    parser.add_argument("--reviewer-b", default=DEFAULT_REVIEWER_B)
    parser.add_argument("--dual-consensus", default=DEFAULT_DUAL_CONSENSUS)
    parser.add_argument("--profile-evaluation", default=DEFAULT_PROFILE_EVALUATION)
    parser.add_argument("--cwe-xml-zip", default=DEFAULT_CWE_ZIP)
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR)
    parser.add_argument("--reviewer-c", default=DEFAULT_REVIEWER_C)
    parser.add_argument("--reviewer-d", default=DEFAULT_REVIEWER_D)
    parser.add_argument("--requests-c", default=DEFAULT_REQUESTS_C)
    parser.add_argument("--requests-d", default=DEFAULT_REQUESTS_D)
    parser.add_argument("--timeout-seconds", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--max-text-chars", type=int, default=DEFAULT_MAX_TEXT_CHARS)
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


def load_unique(path: Path, key: str) -> dict[str, dict]:
    rows = {}
    for row in iter_jsonl(path):
        value = row[key]
        if value in rows:
            raise ValueError(f"duplicate {key}={value} in {path}")
        rows[value] = row
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def recursive_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {
            key for child in value.values() for key in recursive_keys(child)
        }
    if isinstance(value, list):
        return {key for child in value for key in recursive_keys(child)}
    return set()


def derive_fetch_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.netloc.lower() == "github.com":
        path = parsed.path.rstrip("/")
        if "/commit/" in path or "/pull/" in path:
            return f"https://github.com{path}.patch"
        parts = path.split("/")
        if len(parts) >= 6 and parts[3] == "blob":
            owner, repo, _, ref, *rest = parts[1:]
            return (
                f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/"
                + "/".join(rest)
            )
    return url


def reference_rank(url: str) -> tuple[int, str]:
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    if host == "github.com" and "/security/advisories/" in path:
        return (0, url)
    if host == "github.com" and any(
        token in path for token in ("/commit/", "/pull/", "/issues/", "/blob/")
    ):
        return (1, url)
    if any(token in host or token in path for token in ("release", "advisory", "vuln")):
        return (2, url)
    if host == "github.com" and len([part for part in path.split("/") if part]) <= 2:
        return (80, url)
    return (3, url)


def collect_references(source: dict) -> list[dict]:
    combined: dict[str, dict] = {}
    context = source.get("reference_context") or {}
    for database, key in (("nvd", "nvd_urls"), ("ghsa", "ghsa_urls")):
        for raw_url in context.get(key) or []:
            url = str(raw_url).strip()
            if not url:
                continue
            record = combined.setdefault(
                url, {"source_url": url, "source_databases": []}
            )
            if database not in record["source_databases"]:
                record["source_databases"].append(database)
    ranked = sorted(combined.values(), key=lambda item: reference_rank(item["source_url"]))
    selected = [item for item in ranked if reference_rank(item["source_url"])[0] < 80]
    return selected[:MAX_REFERENCES_PER_ROW]


def derive_targets(profile_evaluation: dict) -> list[dict]:
    comparisons = profile_evaluation.get("paired_profile_comparisons") or {}
    comparison = comparisons.get("cwe_taxonomy_v1") or {}
    rows = comparison.get("rows") or []
    if comparison.get("prediction_difference_rows") != TARGET_COUNT or len(rows) != TARGET_COUNT:
        raise ValueError("expected exactly three cwe_taxonomy_v1 prediction differences")
    ordered = sorted(rows, key=lambda row: row["sample_id"])
    for row in ordered:
        if row.get("field") != "cwe_ids":
            raise ValueError("post-profile target is not cwe_ids")
        if row.get("current") == row.get("candidate"):
            raise ValueError("post-profile target does not distinguish profiles")
    if len({row["sample_id"] for row in ordered}) != TARGET_COUNT:
        raise ValueError("duplicate post-profile target sample_id")
    return ordered


def build_blind_row(
    index: int,
    source: dict,
    catalog: CweCatalog,
    cache_dir: Path,
    config: FetchConfig,
) -> tuple[dict, Counter]:
    profile = relation_profile(source["nvd_value"], source["ghsa_value"], catalog)
    if profile["category"] != "disjoint_full_taxonomy_coverage":
        raise ValueError(
            f"unexpected taxonomy profile for {source['sample_id']}: {profile['category']}"
        )
    status_counts = Counter()
    evidence_records = []
    for reference in collect_references(source):
        fetch_url = derive_fetch_url(reference["source_url"])
        fetched, _ = load_or_fetch(fetch_url, cache_dir, config)
        status = fetched.get("fetch_status", "unknown")
        status_counts[status] += 1
        evidence_records.append(
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
        "review_id": f"rq2_post_profile_cwe_evidence_v3:{index:03d}",
        "original_sample_id": source["sample_id"],
        "cve_id": source["cve_id"],
        "field": "cwe_ids",
        "nvd_value": source["nvd_value"],
        "ghsa_value": source["ghsa_value"],
        "official_taxonomy": {
            "source": source["field_context"]["taxonomy_source"],
            "entries": source["field_context"]["official_cwe_entries"],
            "relation_profile": profile,
        },
        "allowed_cwe_path_strings": [
            ">".join(item["cwe_id"] for item in relation["path"])
            for relation in profile["ancestor_descendant_paths"]
        ],
        "vulnerability_context": source["field_context"]["vulnerability_context"],
        "evidence_context": {
            "selection": "up_to_5_ranked_urls_from_frozen_nvd_or_ghsa_references",
            "records": evidence_records,
        },
        "review_contract": {
            "set_relation": [
                "fully_ancestor_descendant_compatible",
                "partially_related_mixed",
                "semantically_distinct",
                "insufficient_taxonomy_or_context",
            ],
            "discrepancy_label": [
                "representation_discrepancy",
                "factual_conflict",
                "uncertain",
            ],
            "taxonomy_support_verdict": [
                "supports_granularity_only",
                "does_not_support_granularity_only",
                "insufficient",
            ],
            "specific_mapping_verdict": [
                "same_mechanism_supported",
                "materially_different_or_contradicted",
                "insufficient",
            ],
            "confidence": ["high", "medium", "low"],
        },
        "conditional_constraints": {
            "representation_discrepancy": {
                "taxonomy_support_verdict": "supports_granularity_only",
                "specific_mapping_verdict": "same_mechanism_supported",
                "confidence": ["high", "medium"],
                "needs_additional_review": False,
                "requires_cwe_path": True,
                "requires_frozen_evidence": True,
            },
            "factual_conflict": {
                "taxonomy_support_verdict": "does_not_support_granularity_only",
                "specific_mapping_verdict": "materially_different_or_contradicted",
                "confidence": ["high", "medium"],
                "needs_additional_review": False,
                "requires_frozen_evidence": True,
            },
            "uncertain": {
                "taxonomy_support_verdict": "insufficient",
                "specific_mapping_verdict": "insufficient",
                "confidence": "low",
                "needs_additional_review": True,
            },
        },
    }
    leaked = recursive_keys(row) & FORBIDDEN_BLIND_KEYS
    if leaked:
        raise ValueError(f"blind row contains forbidden keys: {sorted(leaked)}")
    return row, status_counts


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
        "runner_code": resolve(
            "experiments/rq2_discrepancy_typing/"
            "run_rq2_post_profile_cwe_evidence_review.py"
        ),
        "merge_code": resolve(
            "experiments/rq2_discrepancy_typing/"
            "merge_rq2_post_profile_cwe_evidence_secondary.py"
        ),
        "verifier_code": resolve(
            "experiments/rq2_discrepancy_typing/"
            "verify_rq2_post_profile_cwe_evidence_secondary.py"
        ),
    }
    for name, path in paths.items():
        if not path.is_file():
            raise FileNotFoundError(f"missing {name}: {path}")

    reviewer_paths = {
        "reviewer_c": resolve(args.reviewer_c),
        "reviewer_d": resolve(args.reviewer_d),
        "requests_c": resolve(args.requests_c),
        "requests_d": resolve(args.requests_d),
    }
    existing_reviewers = [str(path) for path in reviewer_paths.values() if path.exists()]
    if existing_reviewers:
        raise ValueError(f"reviewer output exists before sealing: {existing_reviewers}")

    output_dir = resolve(args.output_dir)
    worklist_c_path = output_dir / "worklist_c.blind.jsonl"
    worklist_d_path = output_dir / "worklist_d.blind.jsonl"
    manifest_path = output_dir / "manifest.sealed.json"
    existing_seal = [
        str(path)
        for path in (worklist_c_path, worklist_d_path, manifest_path)
        if path.exists()
    ]
    if existing_seal:
        raise ValueError(f"sealed output already exists: {existing_seal}")

    input_hashes = {name: sha256(path) for name, path in paths.items()}
    evaluation = json.loads(paths["profile_evaluation"].read_text(encoding="utf-8"))
    targets = derive_targets(evaluation)
    source_rows = load_unique(paths["source_rows"], "sample_id")
    predictions = load_unique(paths["predictions"], "sample_id")
    catalog = CweCatalog(paths["cwe_xml_zip"])
    cache_dir = resolve(args.cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    config = FetchConfig(
        timeout_seconds=args.timeout_seconds,
        max_bytes=DEFAULT_MAX_BYTES,
        max_text_chars=args.max_text_chars,
        sleep_seconds=0.2,
        refresh=args.refresh,
    )

    blind_rows = []
    status_counts = Counter()
    selection_rows = []
    for index, target in enumerate(targets, start=1):
        sample_id = target["sample_id"]
        if sample_id not in source_rows or sample_id not in predictions:
            raise ValueError(f"target absent from sealed cohort: {sample_id}")
        prediction = predictions[sample_id]
        if prediction["current"] != target["current"]:
            raise ValueError(f"current prediction mismatch for {sample_id}")
        if prediction["cwe_taxonomy_v1"] != target["candidate"]:
            raise ValueError(f"candidate prediction mismatch for {sample_id}")
        blind_row, row_counts = build_blind_row(
            index, source_rows[sample_id], catalog, cache_dir, config
        )
        blind_rows.append(blind_row)
        status_counts.update(row_counts)
        selection_rows.append(
            {
                "review_id": blind_row["review_id"],
                "sample_id": sample_id,
                "cve_id": target["cve_id"],
                "current": target["current"],
                "candidate": target["candidate"],
                "prior_strict_consensus": target["strict_consensus"],
                "prior_consensus_label": target["consensus_label"],
            }
        )

    for name, path in paths.items():
        if sha256(path) != input_hashes[name]:
            raise ValueError(f"input changed during build: {name}")

    output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(worklist_c_path, blind_rows)
    write_jsonl(worklist_d_path, list(reversed(blind_rows)))
    manifest = {
        "artifact_type": "rq2_post_profile_cwe_evidence_secondary_manifest_v3",
        "sealed_at_ns": time.time_ns(),
        "row_count": TARGET_COUNT,
        "selection": {
            "post_selection_profile_differential": True,
            "selected_after_a_b_unsealing": True,
            "supersedes_failed_v1_contract_attempt": True,
            "supersedes_failed_v2_path_contract_attempt": True,
            "source_profile_comparison": "cwe_taxonomy_v1",
            "rows": selection_rows,
        },
        "claim_boundary": {
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
            "eligible_for_confirmatory_method_gain_claim": False,
            "strict_event_time_claim_allowed": False,
            "candidate_promotion_allowed": False,
            "production_default_changed": False,
        },
        "reviewer_outputs_absent_at_seal": True,
        "evidence_status_counts": dict(sorted(status_counts.items())),
        "inputs": {
            name: {"path": str(path), "sha256": input_hashes[name]}
            for name, path in paths.items()
        },
        "worklists": {
            "reviewer_c": {
                "path": str(worklist_c_path),
                "sha256": sha256(worklist_c_path),
                "order": "target_order",
            },
            "reviewer_d": {
                "path": str(worklist_d_path),
                "sha256": sha256(worklist_d_path),
                "order": "reverse_target_order",
            },
        },
        "reviewer_outputs": {
            name: str(path) for name, path in reviewer_paths.items()
        },
        "builder": {"path": str(Path(__file__)), "sha256": sha256(Path(__file__))},
        "cautions": [
            "The three rows were selected after the original A/B labels and profile evaluation were unsealed.",
            "Both evidence reviewers are Codex runs and are not real humans.",
            "The targeted result cannot replace the sealed 250-row evaluation or estimate unbiased gain.",
        ],
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {worklist_c_path}")
    print(f"Wrote {worklist_d_path}")
    print(f"Wrote {manifest_path}")
    print(json.dumps(manifest["evidence_status_counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
