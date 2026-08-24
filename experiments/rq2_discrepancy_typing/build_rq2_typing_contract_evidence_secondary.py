#!/usr/bin/env python3
"""Build a sealed evidence-backed secondary review for one RQ2 v2 case."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import build_rq2_typing_contract_calibration as v1
import build_rq2_typing_contract_calibration_v2 as v2


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TARGET_SAMPLE_ID = "rq2_typing_holdout_v1:148"
TARGET_CVE_ID = "CVE-2023-29206"
SCHEMA_VERSION = "rq2_typing_contract_evidence_secondary_v1"
ARTIFACT_TYPE = "rq2_typing_contract_evidence_secondary_v1_manifest"
DEFAULT_V2_BASE = "data/annotations/holdout/rq2_typing_v1/contract_calibration_v2"
DEFAULT_V2_RESULTS = "results/holdout/rq2_typing_v1/contract_calibration_v2"
DEFAULT_PROMPT = "docs/prompts/rq2_typing_contract_evidence_secondary.md"
DEFAULT_RUNNER = "scripts/run_expert_candidate_annotation.py"
DEFAULT_OUTPUT_DIR = (
    "data/annotations/holdout/rq2_typing_v1/contract_calibration_v2/"
    "evidence_secondary_v1"
)
DEFAULT_CACHE_DIR = "data/evidence_cache/rq2/typing_contract_evidence_secondary_v1"
MAX_RESPONSE_BYTES = 2_000_000

EVIDENCE_SOURCES = (
    {
        "key": "ghsa_advisory",
        "kind": "security_advisory",
        "source_url": "https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-cmvg-w72j-7phx",
        "fetch_url": "https://api.github.com/advisories/GHSA-cmvg-w72j-7phx",
    },
    {
        "key": "fixing_commit",
        "kind": "fixing_commit",
        "source_url": "https://github.com/xwiki/xwiki-platform/commit/fe65bc35d5672dd2505b7ac4ec42aec57d500fbb",
        "fetch_url": "https://api.github.com/repos/xwiki/xwiki-platform/commits/fe65bc35d5672dd2505b7ac4ec42aec57d500fbb",
    },
    *(
        {
            "key": issue.lower(),
            "kind": "issue",
            "source_url": f"https://jira.xwiki.org/browse/{issue}",
            "fetch_url": f"https://jira.xwiki.org/rest/api/2/issue/{issue}",
        }
        for issue in ("XWIKI-19514", "XWIKI-19583", "XWIKI-9119")
    ),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v2-base", default=DEFAULT_V2_BASE)
    parser.add_argument("--v2-results", default=DEFAULT_V2_RESULTS)
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--runner", default=DEFAULT_RUNNER)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR)
    parser.add_argument("--timeout-seconds", type=int, default=30)
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--review-backend", choices=["openai", "codex-cli"], default="codex-cli")
    parser.add_argument("--review-model", default="gpt-5.5")
    parser.add_argument("--review-max-output-tokens", type=int, default=512)
    parser.add_argument("--codex-cli-path", default="codex")
    parser.add_argument(
        "--codex-reasoning-effort",
        choices=["low", "medium", "high", "xhigh"],
        default="high",
    )
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def body_sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def fetch_json(source: dict, cache_dir: Path, timeout: int, refresh: bool) -> tuple[dict, dict, list[Path]]:
    response_path = cache_dir / f"{source['key']}.response.json"
    metadata_path = cache_dir / f"{source['key']}.fetch.json"
    if response_path.exists() and metadata_path.exists() and not refresh:
        body = response_path.read_bytes()
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        if body_sha256(body) != metadata.get("response_sha256"):
            raise ValueError(f"cached response hash mismatch: {response_path}")
    else:
        request = Request(
            source["fetch_url"],
            headers={
                "Accept": "application/vnd.github+json, application/json",
                "User-Agent": "vuln-adj-rq2-evidence-secondary/1.0",
            },
        )
        with urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise ValueError(f"response exceeds {MAX_RESPONSE_BYTES} bytes: {source['fetch_url']}")
            if response.status != 200:
                raise ValueError(f"HTTP {response.status}: {source['fetch_url']}")
            metadata = {
                "schema_version": SCHEMA_VERSION,
                "source_url": source["source_url"],
                "fetch_url": source["fetch_url"],
                "http_status": response.status,
                "content_type": response.headers.get("Content-Type"),
                "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "response_sha256": body_sha256(body),
                "response_bytes": len(body),
            }
        response_path.write_bytes(body)
        metadata_path.write_text(
            json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    payload = json.loads(body)
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object: {source['fetch_url']}")
    validate_identity(source, payload)
    return payload, metadata, [response_path, metadata_path]


def validate_identity(source: dict, payload: dict) -> None:
    key = source["key"]
    if key == "ghsa_advisory" and (
        payload.get("ghsa_id") != "GHSA-cmvg-w72j-7phx"
        or payload.get("cve_id") != TARGET_CVE_ID
    ):
        raise ValueError("GHSA advisory identity mismatch")
    if key == "fixing_commit" and payload.get("sha") != "fe65bc35d5672dd2505b7ac4ec42aec57d500fbb":
        raise ValueError("fixing commit identity mismatch")
    if source["kind"] == "issue" and payload.get("key") != key.upper():
        raise ValueError(f"Jira issue identity mismatch for {key}")


def normalize_evidence(source: dict, payload: dict, metadata: dict) -> dict:
    if source["key"] == "ghsa_advisory":
        vulnerabilities = []
        for item in payload.get("vulnerabilities") or []:
            package = item.get("package") or {}
            vulnerabilities.append(
                {
                    "ecosystem": package.get("ecosystem"),
                    "package": package.get("name"),
                    "vulnerable_version_range": item.get("vulnerable_version_range"),
                    "patched_versions": item.get("first_patched_version"),
                }
            )
        title = payload.get("summary") or "GHSA-cmvg-w72j-7phx"
        facts = {
            "ghsa_id": payload.get("ghsa_id"),
            "cve_id": payload.get("cve_id"),
            "summary": payload.get("summary"),
            "description": payload.get("description"),
            "vulnerabilities": vulnerabilities,
        }
        published = payload.get("published_at")
    elif source["key"] == "fixing_commit":
        commit = payload.get("commit") or {}
        title = (commit.get("message") or "fixing commit").splitlines()[0]
        facts = {
            "sha": payload.get("sha"),
            "message": commit.get("message"),
            "changed_files": [
                {
                    "filename": item.get("filename"),
                    "status": item.get("status"),
                    "patch": item.get("patch"),
                }
                for item in payload.get("files") or []
            ],
        }
        published = (commit.get("author") or {}).get("date")
    else:
        fields = payload.get("fields") or {}
        title = fields.get("summary") or payload.get("key")
        facts = {
            "issue_key": payload.get("key"),
            "summary": fields.get("summary"),
            "description": fields.get("description"),
            "components": [item.get("name") for item in fields.get("components") or []],
            "fix_versions": [item.get("name") for item in fields.get("fixVersions") or []],
            "status": (fields.get("status") or {}).get("name"),
        }
        published = fields.get("created")
    snippet = json.dumps(facts, ensure_ascii=False, sort_keys=True)
    return {
        "url": source["source_url"],
        "host": urlparse(source["source_url"]).netloc.lower(),
        "title": title,
        "published": published,
        "fetch_status": "ok",
        "fetch_detail": (
            f"Frozen structured API response; HTTP {metadata['http_status']}; "
            f"response_sha256={metadata['response_sha256']}"
        ),
        "fetched_at": metadata["fetched_at"],
        "text_snippet": snippet,
    }


def build_blind_row(source: dict, evidence_records: list[dict]) -> dict:
    blind = v1.holdout.blind_row(source)
    blind["evidence_context"] = {
        "records_total": len(evidence_records),
        "basis": "frozen_official_advisory_fix_commit_and_linked_issue_records",
        "records": evidence_records,
    }
    blind["review_contract"]["minimum_frozen_evidence_urls"] = 2
    forbidden = v1.holdout.forbidden_blind_keys(blind)
    if forbidden:
        raise ValueError(f"secondary blind row contains forbidden keys: {forbidden[:5]}")
    return blind


def main() -> int:
    args = parse_args()
    if args.timeout_seconds < 1 or args.review_max_output_tokens < 1:
        raise ValueError("timeouts and output-token caps must be positive")
    v2_base = resolve(args.v2_base)
    v2_results = resolve(args.v2_results)
    output_dir = resolve(args.output_dir)
    cache_dir = resolve(args.cache_dir)
    prompt_path = resolve(args.prompt)
    runner_path = resolve(args.runner)
    v2_manifest_path = v2_base / "manifest.sealed.json"
    v2_cases_path = v2_results / "dual_review_consensus.jsonl"
    v2_summary_path = v2_results / "summary.json"
    v2_merge_manifest_path = v2_results / "merge_manifest.json"
    source_path = Path(json.loads(v2_manifest_path.read_text(encoding="utf-8"))["outputs"]["source_rows"]["path"])
    source_matches = [row for row in v1.iter_jsonl(source_path) if row.get("sample_id") == TARGET_SAMPLE_ID]
    case_matches = [row for row in v1.iter_jsonl(v2_cases_path) if row.get("sample_id") == TARGET_SAMPLE_ID]
    if len(source_matches) != 1 or len(case_matches) != 1:
        raise ValueError("target sample must occur exactly once in v2 source and result")
    source, parent_case = source_matches[0], case_matches[0]
    if (
        source.get("cve_id") != TARGET_CVE_ID
        or source.get("calibration_stratum") != "affected_prerelease_boundary"
        or parent_case.get("strict_consensus") is not False
        or {parent_case["reviewer_a"]["discrepancy_label"], parent_case["reviewer_b"]["discrepancy_label"]} != {"uncertain"}
    ):
        raise ValueError("target no longer matches the sealed v2 unresolved prerelease contract")
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite sealed secondary directory: {output_dir}")

    cache_dir.mkdir(parents=True, exist_ok=True)
    evidence_records = []
    cache_paths = []
    for evidence_source in EVIDENCE_SOURCES:
        payload, metadata, paths = fetch_json(
            evidence_source, cache_dir, args.timeout_seconds, args.refresh
        )
        evidence_records.append(normalize_evidence(evidence_source, payload, metadata))
        cache_paths.extend(paths)
    allowed_urls = {
        url
        for key in ("nvd_urls", "ghsa_urls")
        for url in source["reference_context"].get(key) or []
    }
    if any(record["url"] not in allowed_urls for record in evidence_records):
        raise ValueError("frozen evidence URL is absent from the original blind references")

    output_dir.mkdir(parents=True, exist_ok=False)
    blind_dir = output_dir / "blind"
    blind_dir.mkdir()
    paths = {
        "source_rows": output_dir / "source_rows.jsonl",
        "blind_worklist_a": blind_dir / "worklist_a.blind.jsonl",
        "blind_worklist_b": blind_dir / "worklist_b.blind.jsonl",
        "manifest": output_dir / "manifest.sealed.json",
        "reviewer_a": output_dir / "reviewer_a.jsonl",
        "reviewer_b": output_dir / "reviewer_b.jsonl",
    }
    source_output = {
        **source,
        "secondary_selection_reason": "v2_reviewers_both_uncertain_on_artifact_identity_and_prerelease_ordering",
        "parent_v2_strict_consensus": False,
        "parent_v2_reviewer_labels": [
            parent_case["reviewer_a"]["discrepancy_label"],
            parent_case["reviewer_b"]["discrepancy_label"],
        ],
    }
    blind = build_blind_row(source, evidence_records)
    v1.write_jsonl(paths["source_rows"], [source_output])
    v1.write_jsonl(paths["blind_worklist_a"], [blind])
    v1.write_jsonl(paths["blind_worklist_b"], [blind])

    execution = (
        v1.holdout.codex_cli_contract(
            args.codex_cli_path, args.review_model, args.codex_reasoning_effort
        )
        if args.review_backend == "codex-cli"
        else v1.holdout.openai_contract(args.review_model, args.review_max_output_tokens)
    )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": ARTIFACT_TYPE,
        "sealed_at_ns": time.time_ns(),
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "development_calibration_only": True,
        "target_sample_id": TARGET_SAMPLE_ID,
        "selected_rows": 1,
        "evidence_records": len(evidence_records),
        "inputs": {
            "v2_manifest": {"path": str(v2_manifest_path), "sha256": v1.sha256(v2_manifest_path)},
            "v2_cases": {"path": str(v2_cases_path), "sha256": v1.sha256(v2_cases_path)},
            "v2_summary": {"path": str(v2_summary_path), "sha256": v1.sha256(v2_summary_path)},
            "v2_merge_manifest": {"path": str(v2_merge_manifest_path), "sha256": v1.sha256(v2_merge_manifest_path)},
            "prompt": {"path": str(prompt_path), "sha256": v1.sha256(prompt_path)},
            "runner": {"path": str(runner_path), "sha256": v1.sha256(runner_path)},
        },
        "evidence_cache": {
            path.name: {"path": str(path), "sha256": v1.sha256(path)}
            for path in sorted(cache_paths)
        },
        "outputs": {
            name: {"path": str(path), "sha256": v1.sha256(path)}
            for name, path in paths.items()
            if name in {"source_rows", "blind_worklist_a", "blind_worklist_b"}
        },
        "review_protocol": {
            "runner_contract_mode": "strict",
            "execution_contract": execution,
            "reviewer_a_pass_id": "rq2_contract_evidence_secondary_v1_reviewer_a",
            "reviewer_b_pass_id": "rq2_contract_evidence_secondary_v1_reviewer_b",
            "reviewer_a_output": str(paths["reviewer_a"]),
            "reviewer_b_output": str(paths["reviewer_b"]),
            "same_prompt_raw_values_and_evidence_for_both_reviewers": True,
            "reviewer_sessions_must_be_disjoint": True,
            "schedule": "input",
            "max_evidence_records": 8,
            "max_evidence_chars": 3200,
            "minimum_cited_frozen_evidence_urls": 2,
        },
    }
    paths["manifest"].write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Wrote {paths['manifest']}")
    print(f"Frozen official evidence records={len(evidence_records)}")
    print("Boundary: one-row non-human development secondary review; no human gold.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
