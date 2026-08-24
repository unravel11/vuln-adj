#!/usr/bin/env python3
"""Build and seal a blind evidence-enhanced audit for 37 unresolved RQ2 rows."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.build_rq3_evidence_samples import (  # noqa: E402
    FetchConfig,
    cache_path_for_url,
    load_or_fetch,
)


SCHEMA_VERSION = "rq2_typing_unresolved_evidence_secondary_v1"
DEFAULT_PARENT_DIR = "results/holdout/rq2_typing_v1/tiebreak_v1"
DEFAULT_SOURCE_WORKLIST = (
    "data/annotations/holdout/rq2_typing_v1/tiebreak_v1/blind/"
    "worklist_c.blind.jsonl"
)
DEFAULT_OUTPUT_DIR = (
    "data/annotations/holdout/rq2_typing_v1/tiebreak_v1/"
    "evidence_secondary_v1"
)
DEFAULT_CACHE_DIR = (
    "data/evidence_cache/rq2/typing_unresolved_evidence_secondary_v1/"
    "url_cache"
)
DEFAULT_PROMPT = "docs/prompts/rq2_typing_unresolved_evidence_review.md"
DEFAULT_CONTRACT = (
    "docs/annotation_guidelines/"
    "rq2_typing_unresolved_evidence_secondary_contract_v1.md"
)
EXPECTED_ROWS = 37
EXPECTED_FIELD_COUNTS = {
    "affected_versions": 28,
    "cwe_ids": 6,
    "references": 2,
    "severity": 1,
}
EXPECTED_GROUP_COUNTS = {
    "one_qualified": 10,
    "three_qualified_split": 7,
    "two_qualified_split": 3,
    "zero_qualified": 17,
}
MIN_EVIDENCE_AVAILABILITY = 0.75
MIN_SECONDARY_STRICT_RESOLUTION = 0.40
MIN_COMBINED_CANDIDATE_COVERAGE = 0.982
MAX_REFERENCES_PER_ROW = 6
RANK_SEED = "rq2_typing_unresolved_evidence_secondary_v1"
FORBIDDEN_BLIND_KEYS = {
    "baseline_status",
    "candidate_label",
    "candidate_resolved",
    "consensus_label",
    "current_prediction",
    "gold_label",
    "qualified_vote_counts",
    "resolution",
    "reviewer_a",
    "reviewer_b",
    "reviewer_c",
    "selection_group",
    "strict_consensus",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent-dir", default=DEFAULT_PARENT_DIR)
    parser.add_argument("--source-worklist", default=DEFAULT_SOURCE_WORKLIST)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR)
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
    parser.add_argument("--timeout-seconds", type=int, default=25)
    parser.add_argument("--max-text-chars", type=int, default=8000)
    parser.add_argument("--refresh", action="store_true")
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def load_unique(path: Path) -> dict[str, dict]:
    rows = {}
    for row in load_jsonl(path):
        sample_id = row.get("sample_id")
        if not sample_id or sample_id in rows:
            raise ValueError(f"{path}: missing or duplicate sample_id={sample_id}")
        rows[sample_id] = row
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def write_json(path: Path, value: dict) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def verified_record(record: dict, name: str) -> Path:
    path = Path(record["path"])
    if not path.is_file() or sha256(path) != record.get("sha256"):
        raise ValueError(f"hash or path mismatch for {name}: {path}")
    return path


def recursive_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {
            key for child in value.values() for key in recursive_keys(child)
        }
    if isinstance(value, list):
        return {key for child in value for key in recursive_keys(child)}
    return set()


def qualified(annotation: dict) -> bool:
    return (
        annotation["discrepancy_label"] != "uncertain"
        and annotation["confidence"] != "low"
        and annotation["needs_human_review"] is False
    )


def vote_group(row: dict) -> str:
    votes = [row["reviewer_a"], row["reviewer_b"], row["reviewer_c"]]
    qualified_labels = [
        annotation["discrepancy_label"] for annotation in votes if qualified(annotation)
    ]
    if not qualified_labels:
        return "zero_qualified"
    if len(qualified_labels) == 1:
        return "one_qualified"
    if len(qualified_labels) == 2:
        return "two_qualified_split"
    return "three_qualified_split"


def derive_fetch_url(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.rstrip("/")
    if host == "github.com":
        if "/commit/" in path or "/pull/" in path:
            return f"https://github.com{path}.patch"
        parts = path.split("/")
        if len(parts) >= 6 and parts[3] == "blob":
            owner, repo, _, ref, *rest = parts[1:]
            return (
                f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/"
                + "/".join(rest)
            )
    if host == "gist.github.com":
        return url.rstrip("/") + "/raw"
    return url


def reference_rank(url: str) -> tuple[int, str]:
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    if host == "nvd.nist.gov":
        return (90, url)
    if host == "github.com" and "/security/advisories/" in path:
        return (0, url)
    if host in {"github.com", "gist.github.com"} and any(
        token in path for token in ("/commit/", "/pull/", "/issues/", "/blob/")
    ):
        return (1, url)
    if any(
        token in host or token in path
        for token in (
            "advisory",
            "bount",
            "bug",
            "cve-",
            "errata",
            "exploit",
            "release",
            "security",
            "vuln",
        )
    ):
        return (2, url)
    if host == "github.com":
        return (80, url)
    return (3, url)


def select_urls(row: dict) -> list[str]:
    context = row.get("reference_context") or {}
    urls = list(
        dict.fromkeys(
            [
                str(url).strip()
                for key in ("nvd_urls", "ghsa_urls")
                for url in (context.get(key) or [])
                if str(url).strip()
            ]
        )
    )
    ranked = sorted(urls, key=reference_rank)
    preferred = [url for url in ranked if reference_rank(url)[0] < 80]
    if not preferred:
        preferred = ranked
    return preferred[:MAX_REFERENCES_PER_ROW]


def rank(sample_id: str) -> str:
    return hashlib.sha256(f"{RANK_SEED}:{sample_id}".encode()).hexdigest()


def verify_execution_contract(contract: dict) -> None:
    path = Path(contract["path"])
    if not path.is_file() or sha256(path) != contract.get("sha256"):
        raise ValueError("execution backend hash drift")
    version = subprocess.run(
        [str(path), "--version"], capture_output=True, text=True, check=True
    ).stdout.strip()
    expected = {
        "backend": "codex-cli",
        "api_route": "codex_cli",
        "version": version,
        "model": "gpt-5.5",
        "reasoning_effort": "medium",
        "max_output_tokens": None,
        "sandbox": "read-only",
        "ephemeral": True,
    }
    drift = {
        key: {"sealed": contract.get(key), "expected": value}
        for key, value in expected.items()
        if contract.get(key) != value
    }
    if drift:
        raise ValueError(f"execution contract drift: {drift}")


def main() -> int:
    args = parse_args()
    parent_dir = resolve(args.parent_dir)
    source_worklist_path = resolve(args.source_worklist)
    output_dir = resolve(args.output_dir)
    cache_dir = resolve(args.cache_dir)
    prompt_path = resolve(args.prompt)
    contract_path = resolve(args.contract)
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite sealed output: {output_dir}")

    parent_result_manifest_path = parent_dir / "manifest.json"
    parent_result_manifest = json.loads(
        parent_result_manifest_path.read_text(encoding="utf-8")
    )
    if parent_result_manifest.get("artifact_type") != "rq2_typing_tiebreak_result_manifest":
        raise ValueError("unexpected parent result manifest")
    if parent_result_manifest.get("label_is_human") is not False:
        raise ValueError("parent candidate must remain non-human")
    for section in ("inputs", "outputs"):
        for name, record in parent_result_manifest[section].items():
            verified_record(record, f"parent.{section}.{name}")

    parent_candidate_path = verified_record(
        parent_result_manifest["outputs"]["candidate"], "parent candidate"
    )
    parent_sealed_path = verified_record(
        parent_result_manifest["inputs"]["sealed_manifest"], "parent seal"
    )
    parent_sealed = json.loads(parent_sealed_path.read_text(encoding="utf-8"))
    execution = parent_sealed["review_protocol"]["execution_contract"]
    verify_execution_contract(execution)
    runner_path = Path(parent_sealed["inputs"]["runner"]["path"])
    predictions_path = Path(parent_sealed["inputs"]["predictions"]["path"])
    for path in (source_worklist_path, prompt_path, contract_path, runner_path, predictions_path):
        if not path.is_file():
            raise FileNotFoundError(path)

    source_worklist = load_unique(source_worklist_path)
    parent_rows = load_jsonl(parent_candidate_path)
    unresolved = [row for row in parent_rows if row["candidate_resolved"] is False]
    field_counts = dict(sorted(Counter(row["field"] for row in unresolved).items()))
    group_counts = dict(sorted(Counter(vote_group(row) for row in unresolved).items()))
    if (
        len(unresolved) != EXPECTED_ROWS
        or field_counts != EXPECTED_FIELD_COUNTS
        or group_counts != EXPECTED_GROUP_COUNTS
    ):
        raise ValueError(
            f"unresolved selection drift: rows={len(unresolved)} "
            f"fields={field_counts} groups={group_counts}"
        )
    if {row["sample_id"] for row in unresolved} - set(source_worklist):
        raise ValueError("an unresolved row is absent from the original blind worklist")

    cache_dir.mkdir(parents=True, exist_ok=True)
    config = FetchConfig(
        timeout_seconds=args.timeout_seconds,
        max_bytes=1_500_000,
        max_text_chars=args.max_text_chars,
        sleep_seconds=0.1,
        refresh=args.refresh,
    )
    blind_rows = []
    triage_rows = []
    status_counts = Counter()
    cache_records = {}
    rows_with_ok_evidence = 0
    unresolved_by_id = {row["sample_id"]: row for row in unresolved}
    for sample_id in sorted(unresolved_by_id, key=rank):
        prior = unresolved_by_id[sample_id]
        source = json.loads(json.dumps(source_worklist[sample_id]))
        selected_urls = select_urls(source)
        evidence_records = []
        row_has_ok = False
        for source_url in selected_urls:
            fetch_url = derive_fetch_url(source_url)
            fetched, _ = load_or_fetch(fetch_url, cache_dir, config)
            cache_path = cache_path_for_url(cache_dir, fetch_url)
            cache_records[fetch_url] = {
                "path": str(cache_path),
                "sha256": sha256(cache_path),
                "source_url": source_url,
            }
            status = fetched.get("fetch_status", "unknown")
            status_counts[status] += 1
            text = fetched.get("text_snippet") or ""
            row_has_ok |= status == "ok" and bool(text.strip())
            evidence_records.append(
                {
                    "url": source_url,
                    "host": fetched.get("host"),
                    "title": fetched.get("title"),
                    "published": fetched.get("published"),
                    "fetch_status": status,
                    "fetch_detail": fetched.get("fetch_detail"),
                    "fetched_at": fetched.get("fetched_at"),
                    "text_snippet": text,
                }
            )
        rows_with_ok_evidence += int(row_has_ok)
        source["evidence_context"] = {
            "candidate_url_count": len(selected_urls),
            "selection": "up_to_6_ranked_urls_from_original_nvd_ghsa_references",
            "records": evidence_records,
        }
        leaked = recursive_keys(source) & FORBIDDEN_BLIND_KEYS
        if leaked:
            raise ValueError(f"blind row leaks prior decision keys: {sorted(leaked)}")
        blind_rows.append(source)
        triage_rows.append(
            {
                "sample_id": sample_id,
                "cve_id": prior["cve_id"],
                "field": prior["field"],
                "label_is_human": False,
                "selection_group": vote_group(prior),
                "reviewer_a": prior["reviewer_a"],
                "reviewer_b": prior["reviewer_b"],
                "reviewer_c": prior["reviewer_c"],
                "evidence_urls": selected_urls,
                "evidence_statuses": [
                    record["fetch_status"] for record in evidence_records
                ],
            }
        )

    output_dir.mkdir(parents=True, exist_ok=False)
    blind_dir = output_dir / "blind"
    blind_dir.mkdir()
    worklist_d_path = blind_dir / "worklist_d.blind.jsonl"
    worklist_e_path = blind_dir / "worklist_e.blind.jsonl"
    triage_path = output_dir / "author_triage.jsonl"
    reviewer_d_path = output_dir / "reviewer_d.jsonl"
    reviewer_e_path = output_dir / "reviewer_e.jsonl"
    requests_d_path = output_dir / "reviewer_d.requests.jsonl"
    requests_e_path = output_dir / "reviewer_e.requests.jsonl"
    manifest_path = output_dir / "manifest.sealed.json"
    write_jsonl(worklist_d_path, blind_rows)
    write_jsonl(worklist_e_path, list(reversed(blind_rows)))
    write_jsonl(triage_path, triage_rows)
    sealed_at_ns = time.time_ns()
    evidence_availability = rows_with_ok_evidence / EXPECTED_ROWS
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "rq2_typing_unresolved_evidence_secondary_manifest",
        "sealed_at_ns": sealed_at_ns,
        "sealed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "development_diagnostic_only": True,
        "post_unsealing": True,
        "selected_rows": EXPECTED_ROWS,
        "field_counts": field_counts,
        "prior_vote_group_counts": group_counts,
        "evidence": {
            "max_references_per_row": MAX_REFERENCES_PER_ROW,
            "rows_with_successful_nonempty_evidence": rows_with_ok_evidence,
            "successful_nonempty_evidence_rate": evidence_availability,
            "fetch_status_counts": dict(sorted(status_counts.items())),
        },
        "thresholds_fixed_before_evidence_fetch": {
            "minimum_evidence_availability": MIN_EVIDENCE_AVAILABILITY,
            "minimum_secondary_strict_resolution": MIN_SECONDARY_STRICT_RESOLUTION,
            "minimum_combined_candidate_coverage": MIN_COMBINED_CANDIDATE_COVERAGE,
        },
        "inputs": {
            "parent_result_manifest": {
                "path": str(parent_result_manifest_path),
                "sha256": sha256(parent_result_manifest_path),
            },
            "parent_candidate": {
                "path": str(parent_candidate_path),
                "sha256": sha256(parent_candidate_path),
            },
            "parent_sealed_manifest": {
                "path": str(parent_sealed_path),
                "sha256": sha256(parent_sealed_path),
            },
            "source_worklist": {
                "path": str(source_worklist_path),
                "sha256": sha256(source_worklist_path),
            },
            "predictions": {
                "path": str(predictions_path),
                "sha256": sha256(predictions_path),
            },
            "prompt": {"path": str(prompt_path), "sha256": sha256(prompt_path)},
            "contract": {
                "path": str(contract_path),
                "sha256": sha256(contract_path),
            },
            "runner": {"path": str(runner_path), "sha256": sha256(runner_path)},
            "fetcher": {
                "path": str(resolve("scripts/build_rq3_evidence_samples.py")),
                "sha256": sha256(resolve("scripts/build_rq3_evidence_samples.py")),
            },
            "builder": {
                "path": str(Path(__file__).resolve()),
                "sha256": sha256(Path(__file__).resolve()),
            },
        },
        "evidence_cache": [
            {"fetch_url": url, **record}
            for url, record in sorted(cache_records.items())
        ],
        "outputs": {
            "blind_worklist_d": {
                "path": str(worklist_d_path),
                "sha256": sha256(worklist_d_path),
            },
            "blind_worklist_e": {
                "path": str(worklist_e_path),
                "sha256": sha256(worklist_e_path),
            },
            "author_triage": {
                "path": str(triage_path),
                "sha256": sha256(triage_path),
                "reviewer_visible": False,
            },
            "reviewer_d": str(reviewer_d_path),
            "reviewer_e": str(reviewer_e_path),
            "reviewer_d_requests": str(requests_d_path),
            "reviewer_e_requests": str(requests_e_path),
        },
        "review_protocol": {
            "runner_contract_mode": "strict",
            "execution_backend": "codex-cli",
            "execution_contract": execution,
            "reviewer_d_pass_id": "rq2_typing_unresolved_evidence_v1_d",
            "reviewer_e_pass_id": "rq2_typing_unresolved_evidence_v1_e",
            "schedule": "input",
            "opposite_input_order": True,
            "minimum_cited_successful_evidence_urls": 1,
            "citation_required_fields": [
                "affected_versions",
                "cwe_ids",
                "references",
            ],
            "resolution_rule": (
                "strict D/E consensus only; prior A/B/C votes are excluded; "
                "citation-required fields need one successful frozen URL per reviewer"
            ),
        },
        "boundary": {
            "same_model_family": True,
            "human_gold_claim_allowed": False,
            "accuracy_claim_allowed": False,
            "confirmatory_claim_allowed": False,
            "production_switch_allowed": False,
            "threshold_relaxation_after_results_allowed": False,
        },
    }
    write_json(manifest_path, manifest)
    print(f"Wrote {worklist_d_path}")
    print(f"Wrote {worklist_e_path}")
    print(f"Wrote {manifest_path}")
    print(
        f"Rows={EXPECTED_ROWS} evidence={rows_with_ok_evidence}/{EXPECTED_ROWS} "
        f"statuses={dict(sorted(status_counts.items()))}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
