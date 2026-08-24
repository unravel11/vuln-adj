#!/usr/bin/env python3
"""Project unresolved Mattermost claims through an official release/commit graph."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "mattermost_release_graph_v3"
DEFAULT_WORKLIST = (
    "data/annotations/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "blind/worklist_d.blind.jsonl"
)
DEFAULT_SEALED_MANIFEST = (
    "data/annotations/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "manifest.sealed.json"
)
DEFAULT_EDGE_AUDIT = (
    "results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "affected_versions_edge_class_audit_v1/analysis.json"
)
DEFAULT_CONTRACT = (
    "docs/annotation_guidelines/affected_versions_mattermost_release_graph_contract_v3.md"
)
DEFAULT_CACHE_DIR = "data/evidence_cache/rq2/mattermost_release_graph_v3"
DEFAULT_OUTPUT_DIR = (
    "results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "mattermost_release_graph_v3"
)
CURRENT_MODULE = "github.com/mattermost/mattermost/server/v8"
LEGACY_MODULE = "github.com/mattermost/mattermost-server"
MAX_RESPONSE_BYTES = 3_000_000
PSEUDO_VERSION = re.compile(r"^(\d+\.\d+\.\d+)-(\d{14})-([0-9a-f]{12})$")
EXPECTED_PRODUCT_VERSIONS = tuple(
    [f"9.11.{patch}" for patch in range(10)]
    + [f"10.3.{patch}" for patch in range(5)]
    + [f"10.4.{patch}" for patch in range(4)]
)
PSEUDO_FIXES = {
    "CVE-2025-22449": "8.0.0-20250102081831-64c566a8280b",
    "CVE-2025-27933": "8.0.0-20250218135018-e644e3c8e393",
}


def range_tuple(start: str | None, end: str | None) -> tuple:
    return ("range", start, True if start is not None else False, end, False)


EXPECTED_SIGNATURES = {
    "CVE-2025-22449": {
        "sample_id": "rq2_typing_holdout_v1:808",
        "nvd": {"mattermost_server": [range_tuple("9.11.0", "9.11.6")]},
        "ghsa": {
            CURRENT_MODULE: [
                range_tuple("9.11.0", "9.11.6"),
                range_tuple(None, PSEUDO_FIXES["CVE-2025-22449"]),
            ]
        },
    },
    "CVE-2025-27933": {
        "sample_id": "rq2_typing_holdout_v1:544",
        "nvd": {
            "mattermost_server": [
                range_tuple("10.3.0", "10.3.4"),
                range_tuple("10.4.0", "10.4.3"),
                range_tuple("9.11.0", "9.11.9"),
            ]
        },
        "ghsa": {
            CURRENT_MODULE: [
                range_tuple("10.3.0", "10.3.4"),
                range_tuple("10.4.0", "10.4.3"),
                range_tuple("9.11.0", "9.11.9"),
                range_tuple(None, PSEUDO_FIXES["CVE-2025-27933"]),
            ],
            LEGACY_MODULE: [range_tuple(None, "9.11.9")],
        },
    },
}


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, raw: str) -> "Version | None":
        match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", raw)
        return cls(*(int(value) for value in match.groups())) if match else None

    def text(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass(frozen=True)
class Source:
    key: str
    url: str
    accepted_statuses: tuple[int, ...] = (200,)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worklist", default=DEFAULT_WORKLIST)
    parser.add_argument("--sealed-manifest", default=DEFAULT_SEALED_MANIFEST)
    parser.add_argument("--edge-audit", default=DEFAULT_EDGE_AUDIT)
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--refresh", action="store_true")
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def bytes_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_sha256(path: Path) -> str:
    return bytes_sha256(path.read_bytes())


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def cache_paths(cache_dir: Path, key: str) -> tuple[Path, Path]:
    return cache_dir / f"{key}.response", cache_dir / f"{key}.fetch.json"


def request_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "vuln-adj-mattermost-release-graph/1.0",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_or_load(
    source: Source,
    cache_dir: Path,
    *,
    timeout_seconds: int,
    refresh: bool,
) -> tuple[bytes, dict]:
    response_path, metadata_path = cache_paths(cache_dir, source.key)
    if response_path.exists() and metadata_path.exists() and not refresh:
        body = response_path.read_bytes()
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        if metadata.get("url") != source.url:
            raise ValueError(f"cached URL drift for {source.key}")
        if metadata.get("response_sha256") != bytes_sha256(body):
            raise ValueError(f"cached response hash mismatch for {source.key}")
    else:
        request = Request(source.url, headers=request_headers())
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                with urlopen(request, timeout=timeout_seconds) as response:
                    status = response.status
                    content_type = response.headers.get("Content-Type")
                    body = response.read(MAX_RESPONSE_BYTES + 1)
                break
            except HTTPError as exc:
                status = exc.code
                content_type = exc.headers.get("Content-Type") if exc.headers else None
                body = exc.read(MAX_RESPONSE_BYTES + 1)
                break
            except (TimeoutError, URLError) as exc:
                last_error = exc
                if attempt == 2:
                    raise RuntimeError(f"failed to fetch {source.url}: {exc}") from exc
                time.sleep(2**attempt)
        else:  # pragma: no cover
            raise RuntimeError(f"failed to fetch {source.url}: {last_error}")
        if len(body) > MAX_RESPONSE_BYTES:
            raise ValueError(f"response exceeds byte limit for {source.key}")
        metadata = {
            "schema_version": SCHEMA_VERSION,
            "url": source.url,
            "http_status": status,
            "content_type": content_type,
            "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "response_sha256": bytes_sha256(body),
            "response_bytes": len(body),
        }
        response_path.write_bytes(body)
        write_json(metadata_path, metadata)
    if metadata.get("http_status") not in source.accepted_statuses:
        raise ValueError(
            f"{source.key}: expected HTTP {source.accepted_statuses}, got {metadata.get('http_status')}"
        )
    return body, metadata


def row_span(item: dict) -> tuple:
    start = item.get("version_start_excluding")
    start_inclusive = False
    if start is None:
        start = item.get("version_start_including")
        start_inclusive = start not in {None, "0"}
    if start in {None, "0"}:
        start = None
        start_inclusive = False
    end = item.get("version_end_excluding")
    end_inclusive = False
    if end is None:
        end = item.get("version_end_including")
        end_inclusive = end is not None
    return ("range", start, start_inclusive, end, end_inclusive)


def claim_signature(items: list[dict]) -> dict[str, list[tuple]]:
    grouped: dict[str, list[tuple]] = {}
    for item in items:
        subject = str(item.get("package_name") or item.get("product"))
        grouped.setdefault(subject, []).append(row_span(item))
    return {subject: sorted(spans, key=str) for subject, spans in sorted(grouped.items())}


def load_fixed_rows(worklist_path: Path, manifest_path: Path, edge_audit_path: Path) -> list[dict]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if file_sha256(worklist_path) != manifest["outputs"]["blind_worklist_d"]["sha256"]:
        raise ValueError("sealed worklist hash mismatch")
    edge_audit = json.loads(edge_audit_path.read_text(encoding="utf-8"))
    if edge_audit["selection"]["selected_family"] != "mattermost":
        raise ValueError("parent edge audit did not select Mattermost")
    expected_ids = set(edge_audit["selection"]["selected_sample_ids"])
    rows = [row for row in load_jsonl(worklist_path) if row.get("sample_id") in expected_ids]
    if len(rows) != 2:
        raise ValueError(f"expected two selected Mattermost rows, found {len(rows)}")
    for row in rows:
        spec = EXPECTED_SIGNATURES.get(row["cve_id"])
        if spec is None or row["sample_id"] != spec["sample_id"]:
            raise ValueError(f"unexpected selected row: {row.get('sample_id')}")
        if claim_signature(row["nvd_value"]) != spec["nvd"]:
            raise ValueError(f"NVD claim drift for {row['cve_id']}")
        if claim_signature(row["ghsa_value"]) != spec["ghsa"]:
            raise ValueError(f"GHSA claim drift for {row['cve_id']}")
    return sorted(rows, key=lambda row: row["cve_id"])


def dynamic_sources(releases: dict[str, str]) -> list[Source]:
    sources: list[Source] = []
    for version, tag in releases.items():
        key = version.replace(".", "_")
        sources.extend([
            Source(
                f"current_gomod_{key}",
                f"https://raw.githubusercontent.com/mattermost/mattermost/{tag}/server/go.mod",
                (200, 404),
            ),
            Source(
                f"legacy_gomod_{key}",
                f"https://raw.githubusercontent.com/mattermost/mattermost-server/{tag}/go.mod",
                (200, 404),
            ),
        ])
    for cve_id, pseudo in PSEUDO_FIXES.items():
        match = PSEUDO_VERSION.fullmatch(pseudo)
        assert match is not None
        _, _, short_sha = match.groups()
        cve_key = cve_id.lower().replace("-", "_")
        sources.extend([
            Source(
                f"{cve_key}_commit",
                f"https://api.github.com/repos/mattermost/mattermost/commits/{short_sha}",
            ),
            Source(
                f"{cve_key}_pseudo_gomod",
                f"https://raw.githubusercontent.com/mattermost/mattermost/{short_sha}/server/go.mod",
                (200, 404),
            ),
        ])
        for version, tag in releases.items():
            version_key = version.replace(".", "_")
            sources.append(Source(
                f"{cve_key}_compare_{version_key}",
                "https://api.github.com/repos/mattermost/mattermost/compare/"
                f"{quote(tag, safe='')}...{short_sha}",
                (200, 404, 409, 422),
            ))
    return sources


def fetch_sources(
    sources: list[Source],
    cache_dir: Path,
    *,
    timeout_seconds: int,
    workers: int,
    refresh: bool,
) -> tuple[dict[str, bytes], dict[str, dict]]:
    bodies: dict[str, bytes] = {}
    metadata: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=workers) as executor:
        pending = {
            executor.submit(
                fetch_or_load,
                source,
                cache_dir,
                timeout_seconds=timeout_seconds,
                refresh=refresh,
            ): source
            for source in sources
        }
        for future in as_completed(pending):
            source = pending[future]
            body, record = future.result()
            bodies[source.key] = body
            metadata[source.key] = record
    return bodies, metadata


def parse_module(body: bytes) -> str | None:
    match = re.search(r"(?m)^module\s+(\S+)\s*$", body.decode("utf-8"))
    return match.group(1) if match else None


def parse_pseudo_commit(cve_id: str, pseudo: str, body: bytes) -> dict:
    match = PSEUDO_VERSION.fullmatch(pseudo)
    if match is None:
        raise ValueError(f"invalid fixed pseudo version for {cve_id}")
    _, timestamp, short_sha = match.groups()
    document = json.loads(body)
    full_sha = str(document.get("sha") or "")
    committer_date = str(((document.get("commit") or {}).get("committer") or {}).get("date") or "")
    expected_date = datetime.strptime(timestamp, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    try:
        observed_date = datetime.fromisoformat(committer_date.replace("Z", "+00:00"))
    except ValueError:
        observed_date = None
    checks = {
        "sha_prefix_matches": full_sha.startswith(short_sha),
        "committer_timestamp_matches": observed_date == expected_date,
    }
    return {
        "cve_id": cve_id,
        "pseudo_version": pseudo,
        "short_sha": short_sha,
        "full_sha": full_sha,
        "expected_committer_timestamp": expected_date.isoformat().replace("+00:00", "Z"),
        "observed_committer_timestamp": committer_date,
        "checks": checks,
        "bound": all(checks.values()),
    }


def ancestry_membership(status: str) -> bool | None:
    if status == "ahead":
        return True
    if status in {"behind", "identical"}:
        return False
    return None


def version_in_span(version: str, span: tuple) -> bool:
    parsed = Version.parse(version)
    if parsed is None:
        raise ValueError(f"unsupported product version: {version}")
    _, start, start_inclusive, end, end_inclusive = span
    lower = Version.parse(start) if start is not None else None
    upper = Version.parse(end) if end is not None else None
    if lower is not None and (parsed < lower or (parsed == lower and not start_inclusive)):
        return False
    if upper is not None and (parsed > upper or (parsed == upper and not end_inclusive)):
        return False
    return True


def set_relation(nvd: set[str], ghsa: set[str]) -> str:
    if nvd == ghsa:
        return "equal"
    if nvd < ghsa:
        return "nvd_subset_of_ghsa"
    if ghsa < nvd:
        return "ghsa_subset_of_nvd"
    if nvd & ghsa:
        return "overlap"
    return "disjoint"


def candidate_for_relation(relation: str) -> str:
    if relation == "equal":
        return "representation_discrepancy"
    if relation in {"nvd_subset_of_ghsa", "ghsa_subset_of_nvd"}:
        return "incomplete"
    return "factual_conflict"


def analyze(
    rows: list[dict],
    releases: dict[str, str],
    bodies: dict[str, bytes],
    metadata: dict[str, dict],
) -> dict:
    current_identity = {}
    legacy_identity = {}
    for version in releases:
        key = version.replace(".", "_")
        current_key = f"current_gomod_{key}"
        current_identity[version] = (
            parse_module(bodies[current_key]) if metadata[current_key]["http_status"] == 200 else None
        )
        legacy_key = f"legacy_gomod_{key}"
        legacy_identity[version] = (
            parse_module(bodies[legacy_key]) if metadata[legacy_key]["http_status"] == 200 else None
        )
    current_total = all(value == CURRENT_MODULE for value in current_identity.values())
    legacy_total = all(value == LEGACY_MODULE for value in legacy_identity.values())

    pseudo_evidence = {}
    for cve_id, pseudo in PSEUDO_FIXES.items():
        cve_key = cve_id.lower().replace("-", "_")
        commit = parse_pseudo_commit(cve_id, pseudo, bodies[f"{cve_key}_commit"])
        pseudo_key = f"{cve_key}_pseudo_gomod"
        pseudo_module = (
            parse_module(bodies[pseudo_key]) if metadata[pseudo_key]["http_status"] == 200 else None
        )
        comparisons = {}
        for version in releases:
            version_key = version.replace(".", "_")
            compare_key = f"{cve_key}_compare_{version_key}"
            if metadata[compare_key]["http_status"] == 200:
                document = json.loads(bodies[compare_key])
                status = document.get("status")
            else:
                status = f"http_{metadata[compare_key]['http_status']}"
            comparisons[version] = {
                "status": status,
                "inside_exclusive_upper_pseudo_interval": ancestry_membership(status),
            }
        pseudo_evidence[cve_id] = {
            "commit": commit,
            "module_identity": pseudo_module,
            "module_identity_bound": pseudo_module == CURRENT_MODULE,
            "comparisons": comparisons,
            "ancestry_total": all(
                item["inside_exclusive_upper_pseudo_interval"] is not None
                for item in comparisons.values()
            ),
        }

    case_results = []
    for row in rows:
        cve_id = row["cve_id"]
        spec = EXPECTED_SIGNATURES[cve_id]
        pseudo = pseudo_evidence[cve_id]
        needs_legacy = LEGACY_MODULE in spec["ghsa"]
        checks = {
            "fixed_input_signature": True,
            "product_release_domain_complete": list(releases) == list(EXPECTED_PRODUCT_VERSIONS),
            "current_module_identity_total": current_total,
            "pseudo_commit_bound": pseudo["commit"]["bound"],
            "pseudo_module_identity_bound": pseudo["module_identity_bound"],
            "pseudo_ancestry_total": pseudo["ancestry_total"],
            "legacy_module_mapping_total": legacy_total if needs_legacy else True,
        }
        passed = all(checks.values())
        nvd_set: set[str] = set()
        ghsa_stable_set: set[str] = set()
        pseudo_set: set[str] = set()
        legacy_set: set[str] = set()
        relation = None
        candidate = "uncertain"
        if passed:
            for version in releases:
                if any(version_in_span(version, span) for span in spec["nvd"]["mattermost_server"]):
                    nvd_set.add(version)
                stable_spans = [
                    span for span in spec["ghsa"][CURRENT_MODULE]
                    if span[3] != PSEUDO_FIXES[cve_id]
                ]
                if any(version_in_span(version, span) for span in stable_spans):
                    ghsa_stable_set.add(version)
                if pseudo["comparisons"][version]["inside_exclusive_upper_pseudo_interval"] is True:
                    pseudo_set.add(version)
                if needs_legacy and legacy_identity[version] == LEGACY_MODULE:
                    legacy_span = spec["ghsa"][LEGACY_MODULE][0]
                    if version_in_span(version, legacy_span):
                        legacy_set.add(version)
            ghsa_set = ghsa_stable_set | pseudo_set | legacy_set
            relation = set_relation(nvd_set, ghsa_set)
            candidate = candidate_for_relation(relation)
        else:
            ghsa_set = set()
        case_results.append({
            "schema_version": SCHEMA_VERSION,
            "sample_id": row["sample_id"],
            "cve_id": cve_id,
            "checks": checks,
            "gate": {
                "passed": passed,
                "status": (
                    "mattermost_release_projection_allowed_development_only"
                    if passed else "abstain_mattermost_release_projection_unresolved"
                ),
                "failed_checks": [name for name, value in checks.items() if not value],
                "development_typing_candidate": candidate,
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
            },
            "release_sets": {
                "nvd": sorted(nvd_set, key=lambda value: Version.parse(value)),
                "ghsa_stable_current_module": sorted(ghsa_stable_set, key=lambda value: Version.parse(value)),
                "ghsa_pseudo_projection": sorted(pseudo_set, key=lambda value: Version.parse(value)),
                "ghsa_legacy_projection": sorted(legacy_set, key=lambda value: Version.parse(value)),
                "ghsa_union": sorted(ghsa_set, key=lambda value: Version.parse(value)),
            } if passed else None,
            "release_set_relation": relation,
            "selection_uses_reviewer_labels": False,
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
        })

    passed_rows = sum(case["gate"]["passed"] for case in case_results)
    advancement_passed = passed_rows == len(case_results)
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "mattermost_release_graph_analysis",
        "product_release_domain": list(releases),
        "product_release_tags": releases,
        "current_module_identity_by_release": current_identity,
        "legacy_module_identity_by_release": legacy_identity,
        "pseudo_evidence": pseudo_evidence,
        "cases": case_results,
        "summary": {
            "row_count": len(case_results),
            "projection_gate_passed": passed_rows,
            "projection_coverage": passed_rows / len(case_results),
            "development_candidate_counts": {
                label: sum(case["gate"]["development_typing_candidate"] == label for case in case_results)
                for label in sorted({case["gate"]["development_typing_candidate"] for case in case_results})
            },
        },
        "advancement_gate": {
            "minimum_projectable_rows": 2,
            "projectable_rows": passed_rows,
            "passed": advancement_passed,
            "status": (
                "advance_mattermost_release_graph_development_only"
                if advancement_passed else "no_go_mattermost_release_graph_unstable"
            ),
            "independent_verification_required": True,
        },
        "boundary": {
            "post_unsealing": True,
            "selection_uses_reviewer_labels": False,
            "development_diagnostic_only": True,
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
            "accuracy_claim_allowed": False,
            "production_switch_allowed": False,
            "generalization_claim_allowed": False,
        },
    }


def render_markdown(analysis: dict) -> str:
    lines = [
        "# Mattermost Release Graph v1",
        "",
        "> Post-unsealing, non-human project-family diagnostic; not an accuracy result.",
        "",
        f"- Product releases: `{len(analysis['product_release_domain'])}`",
        f"- Projection gate passed: `{analysis['summary']['projection_gate_passed']}/{analysis['summary']['row_count']}`",
        f"- Advancement status: `{analysis['advancement_gate']['status']}`",
        "",
        "| CVE | Gate | Failed checks | Relation | Candidate |",
        "|---|---|---|---|---|",
    ]
    for case in analysis["cases"]:
        failed = ", ".join(case["gate"]["failed_checks"]) or "none"
        lines.append(
            f"| {case['cve_id']} | {str(case['gate']['passed']).lower()} | {failed} | "
            f"{case['release_set_relation'] or 'not computed'} | "
            f"{case['gate']['development_typing_candidate']} |"
        )
    lines.extend([
        "",
        "A failed row retains no release-set relation. Diverged commit histories and missing legacy",
        "tag manifests are not replaced by timestamp or identifier similarity.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    worklist_path = resolve(args.worklist)
    manifest_path = resolve(args.sealed_manifest)
    edge_audit_path = resolve(args.edge_audit)
    contract_path = resolve(args.contract)
    cache_dir = resolve(args.cache_dir)
    output_dir = resolve(args.output_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    rows = load_fixed_rows(worklist_path, manifest_path, edge_audit_path)
    releases = {version: f"v{version}" for version in EXPECTED_PRODUCT_VERSIONS}
    sources = dynamic_sources(releases)
    bodies, metadata = fetch_sources(
        sources,
        cache_dir,
        timeout_seconds=args.timeout_seconds,
        workers=args.workers,
        refresh=args.refresh,
    )
    analysis = analyze(rows, releases, bodies, metadata)

    analysis_path = output_dir / "analysis.json"
    summary_path = output_dir / "summary.md"
    write_json(analysis_path, analysis)
    summary_path.write_text(render_markdown(analysis), encoding="utf-8")
    cache_files = sorted(path for path in cache_dir.iterdir() if path.is_file())
    result_manifest = {
        "schema_version": SCHEMA_VERSION,
        "inputs": {
            "worklist": {"path": str(worklist_path), "sha256": file_sha256(worklist_path)},
            "sealed_manifest": {"path": str(manifest_path), "sha256": file_sha256(manifest_path)},
            "edge_audit": {"path": str(edge_audit_path), "sha256": file_sha256(edge_audit_path)},
            "contract": {"path": str(contract_path), "sha256": file_sha256(contract_path)},
        },
        "evidence_cache": {
            path.name: {"path": str(path), "sha256": file_sha256(path)} for path in cache_files
        },
        "outputs": {
            analysis_path.name: {"path": str(analysis_path), "sha256": file_sha256(analysis_path)},
            summary_path.name: {"path": str(summary_path), "sha256": file_sha256(summary_path)},
        },
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
    }
    write_json(output_dir / "manifest.json", result_manifest)
    print(json.dumps({
        "release_count": len(releases),
        "projection_gate_passed": analysis["summary"]["projection_gate_passed"],
        "status": analysis["advancement_gate"]["status"],
        "output_dir": str(output_dir),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
