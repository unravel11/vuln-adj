#!/usr/bin/env python3
"""Build a frozen evidence audit for 16 unresolved post-profile non-CWE rows."""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from pathlib import Path

import build_rq2_typing_unresolved_evidence_secondary as base


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "rq2_post_profile_unresolved_evidence_secondary_v1"
DEFAULT_BASE = "data/annotations/holdout/rq2_post_profile_snapshot_v1"
DEFAULT_MAIN_MERGE = (
    "results/holdout/rq2_post_profile_snapshot_v1/review/merge_manifest.json"
)
DEFAULT_CWE_MERGE = (
    "results/holdout/rq2_post_profile_snapshot_v1/review/"
    "cwe_all50_evidence_v3/merge_manifest.json"
)
DEFAULT_OUTPUT = (
    "data/annotations/holdout/rq2_post_profile_snapshot_v1/"
    "unresolved_evidence_secondary_v1"
)
DEFAULT_CACHE = (
    "data/evidence_cache/rq2/post_profile_unresolved_evidence_secondary_v1/"
    "url_cache"
)
DEFAULT_PROMPT = "docs/prompts/rq2_typing_unresolved_evidence_review.md"
DEFAULT_CONTRACT = (
    "docs/annotation_guidelines/"
    "rq2_post_profile_unresolved_evidence_secondary_contract_v1.md"
)
EXPECTED_ROWS = 16
EXPECTED_FIELD_COUNTS = {"affected_versions": 12, "references": 2, "severity": 2}
EXPECTED_EXCLUDED_CWE_ROWS = 3
MIN_EVIDENCE_AVAILABILITY = 0.75
MIN_SECONDARY_STRICT_RESOLUTION = 0.40
MIN_COMBINED_CANDIDATE_COVERAGE = 0.95
RANK_SEED = SCHEMA_VERSION


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-dir", default=DEFAULT_BASE)
    parser.add_argument("--main-merge", default=DEFAULT_MAIN_MERGE)
    parser.add_argument("--cwe-merge", default=DEFAULT_CWE_MERGE)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT)
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE)
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
    parser.add_argument("--timeout-seconds", type=int, default=25)
    parser.add_argument("--max-text-chars", type=int, default=8000)
    parser.add_argument("--refresh", action="store_true")
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def selection(
    main_rows: list[dict], cwe_rows: list[dict]
) -> tuple[list[dict], list[dict]]:
    unresolved = [row for row in main_rows if not row["strict_consensus"]]
    selected = [row for row in unresolved if row["field"] != "cwe_ids"]
    excluded = [row for row in unresolved if row["field"] == "cwe_ids"]
    cwe_by_original = {row["original_sample_id"]: row for row in cwe_rows}
    if len(excluded) != EXPECTED_EXCLUDED_CWE_ROWS:
        raise ValueError(f"unresolved CWE selection drift: {len(excluded)}")
    for row in excluded:
        secondary = cwe_by_original.get(row["sample_id"])
        if not secondary or not secondary.get("strict_consensus"):
            raise ValueError(f"excluded CWE row lacks strict all-50 result: {row['sample_id']}")
    counts = dict(sorted(Counter(row["field"] for row in selected).items()))
    if len(selected) != EXPECTED_ROWS or counts != EXPECTED_FIELD_COUNTS:
        raise ValueError(f"non-CWE unresolved selection drift: rows={len(selected)} fields={counts}")
    return selected, excluded


def record(path: Path) -> dict:
    return {"path": str(path), "sha256": base.sha256(path)}


def main() -> int:
    args = parse_args()
    base_dir = resolve(args.base_dir)
    output_dir = resolve(args.output_dir)
    cache_dir = resolve(args.cache_dir)
    prompt_path = resolve(args.prompt)
    contract_path = resolve(args.contract)
    main_merge_path = resolve(args.main_merge)
    cwe_merge_path = resolve(args.cwe_merge)
    cohort_manifest_path = base_dir / "manifest.sealed.json"
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite sealed output: {output_dir}")

    cohort = json.loads(cohort_manifest_path.read_text(encoding="utf-8"))
    if cohort.get("artifact_type") != "rq2_post_profile_snapshot_cohort_v1_manifest":
        raise ValueError("unexpected post-profile cohort manifest")
    if cohort.get("boundary", {}).get("label_is_human") is not False:
        raise ValueError("cohort must remain non-human")
    base.verify_execution_contract(cohort["review_protocol"]["execution_contract"])

    main_merge = json.loads(main_merge_path.read_text(encoding="utf-8"))
    cwe_merge = json.loads(cwe_merge_path.read_text(encoding="utf-8"))
    if main_merge.get("artifact_type") != "rq2_post_profile_snapshot_merge_manifest":
        raise ValueError("unexpected main merge manifest")
    if cwe_merge.get("artifact_type") != "rq2_post_profile_cwe_all50_merge_manifest_v3":
        raise ValueError("unexpected CWE merge manifest")
    main_consensus_path = base.verified_record(
        main_merge["outputs"]["consensus"], "main consensus"
    )
    cwe_consensus_path = base.verified_record(
        cwe_merge["outputs"]["consensus"], "CWE all-50 consensus"
    )
    source_worklist_path = base.verified_record(
        cohort["outputs"]["blind_worklist_a"], "source worklist"
    )
    predictions_path = base.verified_record(cohort["outputs"]["predictions"], "predictions")
    runner_path = base.verified_record(cohort["inputs"]["runner"], "runner")
    for path in (prompt_path, contract_path):
        if not path.is_file():
            raise FileNotFoundError(path)

    main_rows = base.load_jsonl(main_consensus_path)
    cwe_rows = base.load_jsonl(cwe_consensus_path)
    selected, excluded_cwe = selection(main_rows, cwe_rows)
    source = base.load_unique(source_worklist_path)
    if {row["sample_id"] for row in selected} - set(source):
        raise ValueError("selected row absent from original blind worklist")

    cache_dir.mkdir(parents=True, exist_ok=True)
    config = base.FetchConfig(
        timeout_seconds=args.timeout_seconds,
        max_bytes=1_500_000,
        max_text_chars=args.max_text_chars,
        sleep_seconds=0.1,
        refresh=args.refresh,
    )
    selected_by_id = {row["sample_id"]: row for row in selected}
    ordered_ids = sorted(
        selected_by_id,
        key=lambda sample_id: base.hashlib.sha256(
            f"{RANK_SEED}:{sample_id}".encode()
        ).hexdigest(),
    )
    blind_rows: list[dict] = []
    triage_rows: list[dict] = []
    cache_records: dict[str, dict] = {}
    status_counts = Counter()
    rows_with_ok_evidence = 0
    for sample_id in ordered_ids:
        prior = selected_by_id[sample_id]
        blind = json.loads(json.dumps(source[sample_id]))
        selected_urls = base.select_urls(blind)
        evidence_records = []
        row_has_ok = False
        for source_url in selected_urls:
            fetch_url = base.derive_fetch_url(source_url)
            fetched, _ = base.load_or_fetch(fetch_url, cache_dir, config)
            cache_path = base.cache_path_for_url(cache_dir, fetch_url)
            cache_records[fetch_url] = {
                "path": str(cache_path),
                "sha256": base.sha256(cache_path),
                "source_url": source_url,
            }
            status = fetched.get("fetch_status", "unknown")
            text = fetched.get("text_snippet") or ""
            status_counts[status] += 1
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
        blind["evidence_context"] = {
            "candidate_url_count": len(selected_urls),
            "selection": "up_to_6_ranked_urls_from_original_nvd_ghsa_references",
            "records": evidence_records,
        }
        leaked = base.recursive_keys(blind) & base.FORBIDDEN_BLIND_KEYS
        if leaked:
            raise ValueError(f"blind row leaks prior decision keys: {sorted(leaked)}")
        blind_rows.append(blind)
        triage_rows.append(
            {
                "sample_id": sample_id,
                "cve_id": prior["cve_id"],
                "field": prior["field"],
                "label_is_human": False,
                "reviewer_a": prior["reviewer_a"],
                "reviewer_b": prior["reviewer_b"],
                "evidence_urls": selected_urls,
                "evidence_statuses": [row["fetch_status"] for row in evidence_records],
            }
        )

    output_dir.mkdir(parents=True, exist_ok=False)
    blind_dir = output_dir / "blind"
    blind_dir.mkdir()
    worklist_g_path = blind_dir / "worklist_g.blind.jsonl"
    worklist_h_path = blind_dir / "worklist_h.blind.jsonl"
    triage_path = output_dir / "author_triage.jsonl"
    manifest_path = output_dir / "manifest.sealed.json"
    base.write_jsonl(worklist_g_path, blind_rows)
    base.write_jsonl(worklist_h_path, list(reversed(blind_rows)))
    base.write_jsonl(triage_path, triage_rows)

    prior_reviewers = {
        "main_reviewer_a": record(Path(cohort["review_protocol"]["reviewer_a_output"])),
        "main_reviewer_b": record(Path(cohort["review_protocol"]["reviewer_b_output"])),
        "cwe_reviewer_e": cwe_merge["inputs"]["reviewer_e"],
        "cwe_reviewer_f": cwe_merge["inputs"]["reviewer_f"],
    }
    sealed_at_ns = time.time_ns()
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "rq2_post_profile_unresolved_evidence_secondary_manifest_v1",
        "sealed_at_ns": sealed_at_ns,
        "sealed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "post_unsealing": True,
        "development_diagnostic_only": True,
        "selected_rows": EXPECTED_ROWS,
        "field_counts": EXPECTED_FIELD_COUNTS,
        "excluded_cwe_rows": [row["sample_id"] for row in excluded_cwe],
        "evidence": {
            "max_references_per_row": base.MAX_REFERENCES_PER_ROW,
            "rows_with_successful_nonempty_evidence": rows_with_ok_evidence,
            "successful_nonempty_evidence_rate": rows_with_ok_evidence / EXPECTED_ROWS,
            "fetch_status_counts": dict(sorted(status_counts.items())),
        },
        "thresholds_fixed_before_evidence_fetch": {
            "minimum_evidence_availability": MIN_EVIDENCE_AVAILABILITY,
            "minimum_secondary_strict_resolution": MIN_SECONDARY_STRICT_RESOLUTION,
            "minimum_combined_candidate_coverage": MIN_COMBINED_CANDIDATE_COVERAGE,
        },
        "inputs": {
            "cohort_manifest": record(cohort_manifest_path),
            "main_merge_manifest": record(main_merge_path),
            "main_consensus": record(main_consensus_path),
            "cwe_merge_manifest": record(cwe_merge_path),
            "cwe_consensus": record(cwe_consensus_path),
            "source_worklist": record(source_worklist_path),
            "predictions": record(predictions_path),
            "prompt": record(prompt_path),
            "contract": record(contract_path),
            "runner": record(runner_path),
            "fetcher": record(resolve("scripts/build_rq3_evidence_samples.py")),
            "builder": record(Path(__file__).resolve()),
            "prior_reviewers": prior_reviewers,
        },
        "evidence_cache": [
            {"fetch_url": url, **value} for url, value in sorted(cache_records.items())
        ],
        "outputs": {
            "blind_worklist_g": record(worklist_g_path),
            "blind_worklist_h": record(worklist_h_path),
            "author_triage": {**record(triage_path), "reviewer_visible": False},
            "reviewer_g": str(output_dir / "reviewer_g.jsonl"),
            "reviewer_h": str(output_dir / "reviewer_h.jsonl"),
            "reviewer_g_requests": str(output_dir / "reviewer_g.requests.jsonl"),
            "reviewer_h_requests": str(output_dir / "reviewer_h.requests.jsonl"),
        },
        "review_protocol": {
            "runner_contract_mode": "strict",
            "execution_backend": "codex-cli",
            "execution_contract": cohort["review_protocol"]["execution_contract"],
            "reviewer_g_pass_id": "rq2_post_profile_unresolved_evidence_v1_g",
            "reviewer_h_pass_id": "rq2_post_profile_unresolved_evidence_v1_h",
            "schedule": "input",
            "opposite_input_order": True,
            "citation_required_fields": ["affected_versions", "references"],
            "resolution_rule": (
                "strict G/H consensus only; prior decisions excluded; citation-required "
                "fields need one successful frozen URL per reviewer"
            ),
        },
        "boundary": {
            "same_model_family": True,
            "human_gold_claim_allowed": False,
            "accuracy_claim_allowed": False,
            "confirmatory_claim_allowed": False,
            "temporal_generalization_claim_allowed": False,
            "candidate_promotion_allowed": False,
            "production_switch_allowed": False,
            "threshold_relaxation_after_results_allowed": False,
        },
    }
    base.write_json(manifest_path, manifest)
    print(f"Wrote {worklist_g_path}")
    print(f"Wrote {worklist_h_path}")
    print(f"Wrote {manifest_path}")
    print(
        f"Rows={EXPECTED_ROWS} evidence={rows_with_ok_evidence}/{EXPECTED_ROWS} "
        f"statuses={dict(sorted(status_counts.items()))}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
