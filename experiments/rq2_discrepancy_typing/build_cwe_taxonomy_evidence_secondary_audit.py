#!/usr/bin/env python3
"""Build and seal a blind evidence-enhanced secondary audit for nine CWE rows."""

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

from scripts.build_rq3_evidence_samples import (  # noqa: E402
    FetchConfig,
    load_or_fetch,
)


DEFAULT_OUTPUT_DIR = (
    "results/rq2_discrepancy_typing/cwe_taxonomy/evidence_secondary_audit"
)
DEFAULT_CACHE_DIR = (
    "data/evidence_cache/rq2/cwe_taxonomy_evidence_secondary/url_cache"
)
DEFAULT_PRIORITY = (
    "results/rq2_discrepancy_typing/cwe_taxonomy/impact_holdout/"
    "cwe_taxonomy_human_priority_worklist.blind.jsonl"
)
DEFAULT_STAGE1_CANDIDATE = (
    "results/rq2_discrepancy_typing/cwe_taxonomy/impact_holdout/"
    "cwe_taxonomy_impact_dual_codex_candidate.jsonl"
)
DEFAULT_STAGE1_AUDIT = (
    "results/rq2_discrepancy_typing/cwe_taxonomy/impact_holdout/"
    "cwe_taxonomy_impact_dual_codex_audit.json"
)
DEFAULT_STAGE1_MANIFEST = (
    "results/rq2_discrepancy_typing/cwe_taxonomy/impact_holdout/"
    "cwe_taxonomy_impact_manifest.sealed.json"
)
DEFAULT_ALIGNED = "data/processed/bootstrap/aligned/nvd_ghsa_by_cve.jsonl"
DEFAULT_PROMPT = "docs/prompts/rq2_cwe_taxonomy_evidence_secondary_review.md"
DEFAULT_AGENT_C = (
    "data/annotations/expert_candidate/batches/"
    "rq2_cwe_taxonomy_evidence_agent_c.jsonl"
)
DEFAULT_AGENT_D = (
    "data/annotations/expert_candidate/batches/"
    "rq2_cwe_taxonomy_evidence_agent_d.jsonl"
)
DEFAULT_TIMEOUT_SECONDS = 25
DEFAULT_MAX_BYTES = 1_500_000
DEFAULT_MAX_TEXT_CHARS = 8_000
MAX_REFERENCES_PER_ROW = 5
FORBIDDEN_BLIND_KEYS = {
    "current_prediction",
    "taxonomy_v1_prediction",
    "consensus_label",
    "strict_consensus",
    "agent_a",
    "agent_b",
    "prior_label",
    "gold_label",
    "label_is_human",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--priority-worklist", default=DEFAULT_PRIORITY)
    parser.add_argument("--stage1-candidate", default=DEFAULT_STAGE1_CANDIDATE)
    parser.add_argument("--stage1-audit", default=DEFAULT_STAGE1_AUDIT)
    parser.add_argument("--stage1-manifest", default=DEFAULT_STAGE1_MANIFEST)
    parser.add_argument("--aligned", default=DEFAULT_ALIGNED)
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--agent-c", default=DEFAULT_AGENT_C)
    parser.add_argument("--agent-d", default=DEFAULT_AGENT_D)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR)
    parser.add_argument("--timeout-seconds", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--max-text-chars", type=int, default=DEFAULT_MAX_TEXT_CHARS)
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--force", action="store_true")
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
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def load_unique(path: Path, key: str) -> dict[str, dict]:
    rows = {}
    for row in iter_jsonl(path):
        value = row[key]
        if value in rows:
            raise ValueError(f"duplicate {key}={value} in {path}")
        rows[value] = row
    return rows


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
    if parsed.netloc.lower() == "gist.github.com":
        return url.rstrip("/") + "/raw"
    return url


def reference_rank(url: str) -> tuple[int, str]:
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    if host in {"nvd.nist.gov", "www.cve.org", "cve.org"}:
        return (100, url)
    if host == "github.com" and "/security/advisories/" in path:
        return (0, url)
    if host in {"github.com", "gist.github.com"} and any(
        token in path
        for token in ("/commit/", "/pull/", "/issues/", "/blob/", "/gist/")
    ):
        return (1, url)
    if host == "gist.github.com":
        return (1, url)
    if any(
        token in host or token in path
        for token in ("pkg.go.dev", "advisory", "release", "vuln", "exploit")
    ):
        return (2, url)
    if host == "github.com" and len([part for part in path.split("/") if part]) <= 2:
        return (80, url)
    return (3, url)


def collect_references(aligned_row: dict) -> list[dict]:
    combined: dict[str, dict] = {}
    source_rows = [("nvd", aligned_row.get("nvd") or {})]
    source_rows.extend(("ghsa", row) for row in aligned_row.get("ghsa") or [])
    for database, source in source_rows:
        for item in source.get("references") or []:
            url = str(item.get("url") or "").strip()
            if not url:
                continue
            record = combined.setdefault(
                url,
                {"source_url": url, "source_databases": [], "source_tags": []},
            )
            if database not in record["source_databases"]:
                record["source_databases"].append(database)
            for tag in item.get("tags") or []:
                if tag not in record["source_tags"]:
                    record["source_tags"].append(tag)
    ranked = sorted(combined.values(), key=lambda item: reference_rank(item["source_url"]))
    selected = [item for item in ranked if reference_rank(item["source_url"])[0] < 80]
    return selected[:MAX_REFERENCES_PER_ROW]


def expected_priority(stage1: dict) -> bool:
    left = stage1["agent_a"]["discrepancy_label"]
    right = stage1["agent_b"]["discrepancy_label"]
    unresolved = left != right or left == "uncertain"
    regression = (
        stage1["strict_consensus"]
        and stage1["consensus_label"] == stage1["current_prediction"]
        and stage1["consensus_label"] != stage1["taxonomy_v1_prediction"]
    )
    return unresolved or regression


def fetch_evidence(
    source: dict,
    aligned_row: dict,
    cache_dir: Path,
    config: FetchConfig,
) -> tuple[dict, Counter]:
    status_counts = Counter()
    records = []
    for reference in collect_references(aligned_row):
        fetch_url = derive_fetch_url(reference["source_url"])
        fetched, _ = load_or_fetch(fetch_url, cache_dir, config)
        status_counts[fetched.get("fetch_status", "unknown")] += 1
        records.append(
            {
                **reference,
                "fetch_url": fetch_url,
                "host": fetched.get("host"),
                "title": fetched.get("title"),
                "published": fetched.get("published"),
                "fetch_status": fetched.get("fetch_status"),
                "fetch_detail": fetched.get("fetch_detail"),
                "fetched_at": fetched.get("fetched_at"),
                "text_snippet": fetched.get("text_snippet") or "",
            }
        )
    worklist = {
        key: value
        for key, value in source.items()
        if key not in {"selection_reason", "review_contract"}
    }
    worklist["evidence_context"] = {
        "selection": "up_to_5_ranked_references_listed_by_nvd_or_ghsa",
        "records": records,
    }
    worklist["review_contract"] = {
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
    }
    leaked = recursive_keys(worklist) & FORBIDDEN_BLIND_KEYS
    if leaked:
        raise ValueError(f"blind row contains forbidden keys: {sorted(leaked)}")
    return worklist, status_counts


def main() -> int:
    args = parse_args()
    paths = {
        "priority_worklist": resolve(args.priority_worklist),
        "stage1_candidate": resolve(args.stage1_candidate),
        "stage1_audit": resolve(args.stage1_audit),
        "stage1_manifest": resolve(args.stage1_manifest),
        "aligned": resolve(args.aligned),
        "prompt": resolve(args.prompt),
        "fetcher_code": resolve("scripts/build_rq3_evidence_samples.py"),
        "agent_c": resolve(args.agent_c),
        "agent_d": resolve(args.agent_d),
    }
    if paths["agent_c"].exists() or paths["agent_d"].exists():
        raise ValueError("secondary reviewer output exists before sealing")

    output_dir = resolve(args.output_dir)
    cache_dir = resolve(args.cache_dir)
    worklist_path = output_dir / "cwe_taxonomy_evidence_secondary_worklist.blind.jsonl"
    manifest_path = output_dir / "cwe_taxonomy_evidence_secondary_manifest.sealed.json"
    if not args.force and (worklist_path.exists() or manifest_path.exists()):
        raise ValueError("sealed secondary output already exists")

    priority = list(iter_jsonl(paths["priority_worklist"]))
    stage1 = load_unique(paths["stage1_candidate"], "review_id")
    if len(priority) != 9 or len(stage1) != 17:
        raise ValueError("expected 9 priority and 17 stage-one rows")
    expected_ids = {review_id for review_id, row in stage1.items() if expected_priority(row)}
    priority_ids = {row["review_id"] for row in priority}
    if priority_ids != expected_ids:
        raise ValueError("priority worklist does not match stage-one priority contract")

    aligned = load_unique(paths["aligned"], "cve_id")
    cache_dir.mkdir(parents=True, exist_ok=True)
    config = FetchConfig(
        timeout_seconds=args.timeout_seconds,
        max_bytes=DEFAULT_MAX_BYTES,
        max_text_chars=args.max_text_chars,
        sleep_seconds=0.2,
        refresh=args.refresh,
    )
    rows = []
    status_counts = Counter()
    for source in priority:
        row, row_counts = fetch_evidence(
            source, aligned[source["cve_id"]], cache_dir, config
        )
        rows.append(row)
        status_counts.update(row_counts)

    output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(worklist_path, rows)
    sealed_at_ns = time.time_ns()
    manifest = {
        "artifact_type": "rq2_cwe_taxonomy_evidence_secondary_manifest",
        "sealed_at_ns": sealed_at_ns,
        "row_count": len(rows),
        "reviewer_outputs_absent_at_seal": True,
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_confirmatory_claim": False,
        "worklist": {"path": str(worklist_path), "sha256": sha256(worklist_path)},
        "evidence_status_counts": dict(sorted(status_counts.items())),
        "inputs": {
            name: {"path": str(path), "sha256": sha256(path)}
            for name, path in paths.items()
            if name not in {"agent_c", "agent_d"}
        },
        "reviewer_outputs": {
            "agent_c": str(paths["agent_c"]),
            "agent_d": str(paths["agent_d"]),
        },
        "code": {"path": str(Path(__file__)), "sha256": sha256(Path(__file__))},
        "cautions": [
            "Selection is conditional on stage-one disagreement or candidate regression.",
            "Frozen web snapshots can be incomplete, unavailable, or secondary sources.",
            "Both secondary reviewers will be Codex runs, not real humans.",
        ],
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {worklist_path}")
    print(f"Wrote {manifest_path}")
    print(json.dumps(manifest["evidence_status_counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
