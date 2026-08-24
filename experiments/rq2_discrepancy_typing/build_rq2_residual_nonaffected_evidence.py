#!/usr/bin/env python3
"""Freeze the three revealed non-affected RQ2 residual rows and official evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "rq2_residual_nonaffected_evidence_v1"
DEFAULT_SOURCE = "data/annotations/holdout/rq2_typing_v1/source_rows.jsonl"
DEFAULT_CONSENSUS = (
    "results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "dual_review_consensus.jsonl"
)
DEFAULT_CONTRACT = (
    "docs/annotation_guidelines/rq2_residual_nonaffected_evidence_contract_v1.md"
)
DEFAULT_OUTPUT_DIR = (
    "data/annotations/holdout/rq2_typing_v1/tiebreak_v1/"
    "residual_nonaffected_evidence_v1"
)
DEFAULT_CACHE_DIR = "data/evidence_cache/rq2/residual_nonaffected_evidence_v1"

LIGHTNING_COMMIT = "056bb0834b8fca739dec3e731b01f2f6631be142"
FROXLOR_COMMIT = "ce9a5f97a3edb30c7d33878765d3c014a6583597"
EXPECTED_ROWS = {
    "rq2_typing_holdout_v1:1118": ("CVE-2024-8020", "cwe_ids"),
    "rq2_typing_holdout_v1:1023": ("CVE-2023-4304", "cwe_ids"),
    "rq2_typing_holdout_v1:787": ("CVE-2023-32187", "references"),
}
EVIDENCE_URLS = {
    "lightning_api_source": (
        "https://raw.githubusercontent.com/Lightning-AI/pytorch-lightning/"
        f"{LIGHTNING_COMMIT}/src/lightning/app/core/api.py"
    ),
    "lightning_advisory": "https://api.github.com/advisories/GHSA-98fp-7v67-4v3q",
    "cwe_248": "https://cwe.mitre.org/data/definitions/248.html",
    "cwe_400": "https://cwe.mitre.org/data/definitions/400.html",
    "froxlor_patch": f"https://github.com/froxlor/froxlor/commit/{FROXLOR_COMMIT}.patch",
    "froxlor_advisory": "https://api.github.com/advisories/GHSA-9rmf-6qgj-g3wj",
    "cwe_840": "https://cwe.mitre.org/data/definitions/840.html",
    "cwe_284": "https://cwe.mitre.org/data/definitions/284.html",
    "cwe_862": "https://cwe.mitre.org/data/definitions/862.html",
    "k3s_advisory": "https://api.github.com/advisories/GHSA-m4hf-6vgr-75r2",
    "suse_malformed_single_slash": (
        "https://bugzilla.suse.com/show_bug.cgi?id=CVE-2023-32187https:/"
    ),
    "suse_malformed_double_slash": (
        "https://bugzilla.suse.com/show_bug.cgi?id=CVE-2023-32187https://"
    ),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=DEFAULT_SOURCE)
    parser.add_argument("--consensus", default=DEFAULT_CONSENSUS)
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR)
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def portable_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path.resolve())


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def load_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def select_residual(consensus_rows: list[dict]) -> list[dict]:
    selected = [
        row
        for row in consensus_rows
        if row.get("secondary_strict_consensus") is False
        and row.get("field") != "affected_versions"
    ]
    actual = {
        row.get("sample_id"): (row.get("cve_id"), row.get("field"))
        for row in selected
    }
    if actual != EXPECTED_ROWS:
        raise ValueError(f"residual cohort drift: {actual!r}")
    return sorted(selected, key=lambda row: row["sample_id"])


def worklist_projection(source: dict) -> dict:
    allowed = (
        "sample_id",
        "cve_id",
        "field",
        "nvd_source_id",
        "ghsa_source_id",
        "nvd_value",
        "ghsa_value",
        "field_context",
        "reference_context",
        "package_names",
        "source_line_number",
    )
    return {key: source[key] for key in allowed if key in source}


def cache_paths(cache_dir: Path, url: str) -> tuple[Path, Path]:
    key = sha256_bytes(url.encode("utf-8"))
    return cache_dir / f"{key}.body", cache_dir / f"{key}.metadata.json"


def fetch(url: str) -> tuple[bytes, dict]:
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json, text/plain, text/html;q=0.9, */*;q=0.1",
            "User-Agent": "vuln-adj-rq2-residual-evidence-v1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urlopen(request, timeout=90) as response:
        body = response.read()
        metadata = {
            "requested_url": url,
            "final_url": response.geturl(),
            "http_status": response.status,
            "content_type": response.headers.get("Content-Type", ""),
            "etag": response.headers.get("ETag"),
            "last_modified": response.headers.get("Last-Modified"),
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "body_bytes": len(body),
            "body_sha256": sha256_bytes(body),
        }
    return body, metadata


def freeze_evidence(cache_dir: Path, force: bool) -> dict[str, dict]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    records = {}
    for name, url in EVIDENCE_URLS.items():
        body_path, metadata_path = cache_paths(cache_dir, url)
        if body_path.exists() or metadata_path.exists():
            if not force or not (body_path.exists() and metadata_path.exists()):
                if not (body_path.exists() and metadata_path.exists()):
                    raise ValueError(f"partial cache record for {name}")
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                if sha256(body_path) != metadata.get("body_sha256"):
                    raise ValueError(f"cache hash mismatch for {name}")
                records[name] = {
                    "url": url,
                    "body_path": portable_path(body_path),
                    "metadata_path": portable_path(metadata_path),
                    "body_sha256": metadata["body_sha256"],
                    "metadata_sha256": sha256(metadata_path),
                }
                continue
        body, metadata = fetch(url)
        if metadata["http_status"] != 200 or not body:
            raise ValueError(f"unusable evidence response for {name}: {metadata}")
        body_path.write_bytes(body)
        metadata_path.write_text(canonical_json(metadata), encoding="utf-8")
        records[name] = {
            "url": url,
            "body_path": portable_path(body_path),
            "metadata_path": portable_path(metadata_path),
            "body_sha256": sha256(body_path),
            "metadata_sha256": sha256(metadata_path),
        }
    return records


def main() -> int:
    args = parse_args()
    source_path = resolve(args.source)
    consensus_path = resolve(args.consensus)
    contract_path = resolve(args.contract)
    output_dir = resolve(args.output_dir)
    cache_dir = resolve(args.cache_dir)
    worklist_path = output_dir / "worklist.evidence.jsonl"
    manifest_path = output_dir / "manifest.sealed.json"

    if manifest_path.exists() and not args.force:
        raise FileExistsError(f"refusing to overwrite sealed manifest: {manifest_path}")
    for path in (source_path, consensus_path, contract_path):
        if not path.is_file():
            raise FileNotFoundError(path)

    selected = select_residual(load_jsonl(consensus_path))
    source_by_id = {row["sample_id"]: row for row in load_jsonl(source_path)}
    worklist = []
    for row in selected:
        source = source_by_id.get(row["sample_id"])
        if source is None:
            raise ValueError(f"missing source row {row['sample_id']}")
        if (source["cve_id"], source["field"]) != (
            row["cve_id"],
            row["field"],
        ):
            raise ValueError(f"source identity drift for {row['sample_id']}")
        worklist.append(worklist_projection(source))

    evidence = freeze_evidence(cache_dir, args.force)
    output_dir.mkdir(parents=True, exist_ok=True)
    worklist_path.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in worklist),
        encoding="utf-8",
    )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "rq2_residual_nonaffected_evidence_seal",
        "sealed_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "source": {"path": portable_path(source_path), "sha256": sha256(source_path)},
            "consensus": {"path": portable_path(consensus_path), "sha256": sha256(consensus_path)},
            "contract": {"path": portable_path(contract_path), "sha256": sha256(contract_path)},
            "builder": {
                "path": portable_path(Path(__file__).resolve()),
                "sha256": sha256(Path(__file__).resolve()),
            },
        },
        "output": {
            "worklist": {
                "path": portable_path(worklist_path),
                "sha256": sha256(worklist_path),
                "row_count": len(worklist),
            }
        },
        "evidence": evidence,
        "selection": {
            "rule": "secondary_strict_consensus_false_and_field_not_affected_versions",
            "sample_ids": [row["sample_id"] for row in worklist],
            "selection_uses_prior_unresolved_status": True,
            "reviewer_rationales_copied_to_worklist": False,
            "candidate_labels_copied_to_worklist": False,
        },
        "post_unsealing_targeted_diagnostic": True,
        "protocol_discovery_disclosed": True,
        "candidate_promotion_allowed": False,
        "eligible_for_human_gold_claim": False,
        "label_is_human": False,
    }
    manifest_path.write_text(canonical_json(manifest), encoding="utf-8")
    print(
        json.dumps(
            {
                "output_dir": str(output_dir),
                "row_count": len(worklist),
                "evidence_records": len(evidence),
                "candidate_promotion_allowed": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
