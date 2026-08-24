#!/usr/bin/env python3
"""Independently verify the cached Mattermost Git-tag graph diagnostic."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "mattermost_release_graph_v3"
DEFAULT_MANIFEST = (
    "results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "mattermost_release_graph_v3/manifest.json"
)
CURRENT_MODULE = "github.com/mattermost/mattermost/server/v8"
LEGACY_MODULE = "github.com/mattermost/mattermost-server"
VERSIONS = tuple(
    [f"9.11.{patch}" for patch in range(10)]
    + [f"10.3.{patch}" for patch in range(5)]
    + [f"10.4.{patch}" for patch in range(4)]
)
PSEUDOS = {
    "CVE-2025-22449": "8.0.0-20250102081831-64c566a8280b",
    "CVE-2025-27933": "8.0.0-20250218135018-e644e3c8e393",
}
SPECS = {
    "CVE-2025-22449": {
        "sample_id": "rq2_typing_holdout_v1:808",
        "nvd": [("9.11.0", "9.11.6")],
        "stable": [("9.11.0", "9.11.6")],
        "legacy": False,
    },
    "CVE-2025-27933": {
        "sample_id": "rq2_typing_holdout_v1:544",
        "nvd": [("10.3.0", "10.3.4"), ("10.4.0", "10.4.3"), ("9.11.0", "9.11.9")],
        "stable": [("10.3.0", "10.3.4"), ("10.4.0", "10.4.3"), ("9.11.0", "9.11.9")],
        "legacy": True,
    },
}
PSEUDO_PATTERN = re.compile(r"^(\d+\.\d+\.\d+)-(\d{14})-([0-9a-f]{12})$")


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, raw: str) -> "Version":
        match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", raw)
        if match is None:
            raise ValueError(f"unsupported semantic version: {raw}")
        return cls(*(int(value) for value in match.groups()))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verified_record(record: dict, name: str) -> Path:
    path = resolve(record["path"])
    if not path.is_file():
        raise ValueError(f"{name} is missing: {path}")
    if file_sha256(path) != record.get("sha256"):
        raise ValueError(f"{name} hash mismatch")
    return path


def verified_cache_pair(cache_paths: dict[str, Path], key: str, url: str) -> tuple[bytes, dict]:
    body = cache_paths[f"{key}.response"].read_bytes()
    metadata = json.loads(cache_paths[f"{key}.fetch.json"].read_text(encoding="utf-8"))
    if metadata.get("url") != url:
        raise ValueError(f"cache URL mismatch for {key}")
    if metadata.get("response_sha256") != hashlib.sha256(body).hexdigest():
        raise ValueError(f"cache response hash mismatch for {key}")
    return body, metadata


def parse_module(body: bytes) -> str | None:
    match = re.search(r"(?m)^module\s+(\S+)\s*$", body.decode("utf-8"))
    return match.group(1) if match else None


def ancestry_membership(status: str) -> bool | None:
    if status == "ahead":
        return True
    if status in {"behind", "identical"}:
        return False
    return None


def parse_commit(cve_id: str, body: bytes) -> dict:
    pseudo = PSEUDOS[cve_id]
    match = PSEUDO_PATTERN.fullmatch(pseudo)
    if match is None:
        raise ValueError("fixed pseudo version is invalid")
    _, timestamp, short_sha = match.groups()
    document = json.loads(body)
    full_sha = str(document.get("sha") or "")
    observed_timestamp = str(
        ((document.get("commit") or {}).get("committer") or {}).get("date") or ""
    )
    expected = datetime.strptime(timestamp, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    try:
        observed = datetime.fromisoformat(observed_timestamp.replace("Z", "+00:00"))
    except ValueError:
        observed = None
    checks = {
        "sha_prefix_matches": full_sha.startswith(short_sha),
        "committer_timestamp_matches": observed == expected,
    }
    return {
        "cve_id": cve_id,
        "pseudo_version": pseudo,
        "short_sha": short_sha,
        "full_sha": full_sha,
        "expected_committer_timestamp": expected.isoformat().replace("+00:00", "Z"),
        "observed_committer_timestamp": observed_timestamp,
        "checks": checks,
        "bound": all(checks.values()),
    }


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
    return {key: sorted(value, key=str) for key, value in sorted(grouped.items())}


def expected_claims(cve_id: str) -> tuple[dict, dict]:
    spec = SPECS[cve_id]
    nvd = {
        "mattermost_server": sorted(
            [("range", start, True, end, False) for start, end in spec["nvd"]],
            key=str,
        )
    }
    current = [
        *(('range', start, True, end, False) for start, end in spec["stable"]),
        ("range", None, False, PSEUDOS[cve_id], False),
    ]
    ghsa = {CURRENT_MODULE: sorted(current, key=str)}
    if spec["legacy"]:
        ghsa[LEGACY_MODULE] = [("range", None, False, "9.11.9", False)]
    return nvd, {key: ghsa[key] for key in sorted(ghsa)}


def in_span(version: str, start: str, end: str) -> bool:
    parsed = Version.parse(version)
    return Version.parse(start) <= parsed < Version.parse(end)


def relation(left: set[str], right: set[str]) -> str:
    if left == right:
        return "equal"
    if left < right:
        return "nvd_subset_of_ghsa"
    if right < left:
        return "ghsa_subset_of_nvd"
    if left & right:
        return "overlap"
    return "disjoint"


def relation_candidate(value: str) -> str:
    if value == "equal":
        return "representation_discrepancy"
    if value in {"nvd_subset_of_ghsa", "ghsa_subset_of_nvd"}:
        return "incomplete"
    return "factual_conflict"


def expected_cache_inventory() -> set[str]:
    keys = set()
    for version in VERSIONS:
        suffix = version.replace(".", "_")
        keys.update({f"current_gomod_{suffix}", f"legacy_gomod_{suffix}"})
    for cve_id, pseudo in PSEUDOS.items():
        cve_key = cve_id.lower().replace("-", "_")
        keys.update({f"{cve_key}_commit", f"{cve_key}_pseudo_gomod"})
        keys.update(f"{cve_key}_compare_{version.replace('.', '_')}" for version in VERSIONS)
    return {f"{key}.{suffix}" for key in keys for suffix in ("response", "fetch.json")}


def validate(manifest: dict) -> dict:
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unexpected manifest schema")
    inputs = {
        name: verified_record(record, f"input:{name}")
        for name, record in manifest["inputs"].items()
    }
    analysis_path = verified_record(manifest["outputs"]["analysis.json"], "output:analysis")
    verified_record(manifest["outputs"]["summary.md"], "output:summary")
    cache_paths = {
        name: verified_record(record, f"cache:{name}")
        for name, record in manifest["evidence_cache"].items()
    }
    if set(cache_paths) != expected_cache_inventory():
        raise ValueError("evidence cache inventory differs from fixed v3 graph")

    sealed = json.loads(inputs["sealed_manifest"].read_text(encoding="utf-8"))
    if sealed["outputs"]["blind_worklist_d"]["sha256"] != file_sha256(inputs["worklist"]):
        raise ValueError("worklist seal mismatch")
    edge_audit = json.loads(inputs["edge_audit"].read_text(encoding="utf-8"))
    if edge_audit["selection"]["selected_family"] != "mattermost":
        raise ValueError("edge audit selection drift")
    rows = {
        row["cve_id"]: row
        for row in (
            json.loads(line)
            for line in inputs["worklist"].read_text(encoding="utf-8").splitlines()
            if line
        )
        if row.get("cve_id") in SPECS
    }
    if set(rows) != set(SPECS):
        raise ValueError("fixed Mattermost rows are missing")
    for cve_id, spec in SPECS.items():
        row = rows[cve_id]
        if row.get("sample_id") != spec["sample_id"] or row.get("field") != "affected_versions":
            raise ValueError(f"fixed row identity drift for {cve_id}")
        expected_nvd, expected_ghsa = expected_claims(cve_id)
        if claim_signature(row["nvd_value"]) != expected_nvd:
            raise ValueError(f"NVD claim drift for {cve_id}")
        if claim_signature(row["ghsa_value"]) != expected_ghsa:
            raise ValueError(f"GHSA claim drift for {cve_id}")

    tags = {version: f"v{version}" for version in VERSIONS}
    current_identity = {}
    legacy_identity = {}
    for version, tag in tags.items():
        suffix = version.replace(".", "_")
        body, metadata = verified_cache_pair(
            cache_paths,
            f"current_gomod_{suffix}",
            f"https://raw.githubusercontent.com/mattermost/mattermost/{tag}/server/go.mod",
        )
        if metadata.get("http_status") not in {200, 404}:
            raise ValueError(f"unexpected current manifest status for {version}")
        current_identity[version] = parse_module(body) if metadata["http_status"] == 200 else None
        body, metadata = verified_cache_pair(
            cache_paths,
            f"legacy_gomod_{suffix}",
            f"https://raw.githubusercontent.com/mattermost/mattermost-server/{tag}/go.mod",
        )
        if metadata.get("http_status") not in {200, 404}:
            raise ValueError(f"unexpected legacy manifest status for {version}")
        legacy_identity[version] = parse_module(body) if metadata["http_status"] == 200 else None

    pseudo_evidence = {}
    for cve_id, pseudo in PSEUDOS.items():
        cve_key = cve_id.lower().replace("-", "_")
        short_sha = PSEUDO_PATTERN.fullmatch(pseudo).group(3)
        commit_body, metadata = verified_cache_pair(
            cache_paths,
            f"{cve_key}_commit",
            f"https://api.github.com/repos/mattermost/mattermost/commits/{short_sha}",
        )
        if metadata.get("http_status") != 200:
            raise ValueError(f"pseudo commit is not HTTP 200 for {cve_id}")
        commit = parse_commit(cve_id, commit_body)
        module_body, metadata = verified_cache_pair(
            cache_paths,
            f"{cve_key}_pseudo_gomod",
            f"https://raw.githubusercontent.com/mattermost/mattermost/{short_sha}/server/go.mod",
        )
        module_identity = parse_module(module_body) if metadata.get("http_status") == 200 else None
        comparisons = {}
        for version, tag in tags.items():
            suffix = version.replace(".", "_")
            body, metadata = verified_cache_pair(
                cache_paths,
                f"{cve_key}_compare_{suffix}",
                "https://api.github.com/repos/mattermost/mattermost/compare/"
                f"{quote(tag, safe='')}...{short_sha}",
            )
            if metadata.get("http_status") == 200:
                status = json.loads(body).get("status")
            elif metadata.get("http_status") in {404, 409, 422}:
                status = f"http_{metadata['http_status']}"
            else:
                raise ValueError(f"unexpected compare status for {cve_id} {version}")
            comparisons[version] = {
                "status": status,
                "inside_exclusive_upper_pseudo_interval": ancestry_membership(status),
            }
        pseudo_evidence[cve_id] = {
            "commit": commit,
            "module_identity": module_identity,
            "module_identity_bound": module_identity == CURRENT_MODULE,
            "comparisons": comparisons,
            "ancestry_total": all(
                item["inside_exclusive_upper_pseudo_interval"] is not None
                for item in comparisons.values()
            ),
        }

    current_total = all(value == CURRENT_MODULE for value in current_identity.values())
    legacy_total = all(value == LEGACY_MODULE for value in legacy_identity.values())
    expected_cases = []
    for cve_id in sorted(SPECS):
        spec = SPECS[cve_id]
        pseudo = pseudo_evidence[cve_id]
        checks = {
            "fixed_input_signature": True,
            "product_release_domain_complete": True,
            "current_module_identity_total": current_total,
            "pseudo_commit_bound": pseudo["commit"]["bound"],
            "pseudo_module_identity_bound": pseudo["module_identity_bound"],
            "pseudo_ancestry_total": pseudo["ancestry_total"],
            "legacy_module_mapping_total": legacy_total if spec["legacy"] else True,
        }
        passed = all(checks.values())
        release_sets = None
        set_relation = None
        candidate = "uncertain"
        if passed:
            nvd = {v for v in VERSIONS if any(in_span(v, *span) for span in spec["nvd"])}
            stable = {v for v in VERSIONS if any(in_span(v, *span) for span in spec["stable"])}
            pseudo_set = {
                v for v in VERSIONS
                if pseudo["comparisons"][v]["inside_exclusive_upper_pseudo_interval"] is True
            }
            legacy = {
                v for v in VERSIONS
                if spec["legacy"] and legacy_identity[v] == LEGACY_MODULE and in_span(v, "0.0.0", "9.11.9")
            }
            ghsa = stable | pseudo_set | legacy
            set_relation = relation(nvd, ghsa)
            candidate = relation_candidate(set_relation)
            order = lambda value: Version.parse(value)
            release_sets = {
                "nvd": sorted(nvd, key=order),
                "ghsa_stable_current_module": sorted(stable, key=order),
                "ghsa_pseudo_projection": sorted(pseudo_set, key=order),
                "ghsa_legacy_projection": sorted(legacy, key=order),
                "ghsa_union": sorted(ghsa, key=order),
            }
        expected_cases.append({
            "schema_version": SCHEMA_VERSION,
            "sample_id": spec["sample_id"],
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
            "release_sets": release_sets,
            "release_set_relation": set_relation,
            "selection_uses_reviewer_labels": False,
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
        })

    observed = json.loads(analysis_path.read_text(encoding="utf-8"))
    if observed.get("product_release_domain") != list(VERSIONS) or observed.get("product_release_tags") != tags:
        raise ValueError("fixed Git-tag domain differs from independent reconstruction")
    if observed.get("current_module_identity_by_release") != current_identity:
        raise ValueError("current module mappings differ from cache")
    if observed.get("legacy_module_identity_by_release") != legacy_identity:
        raise ValueError("legacy module mappings differ from cache")
    if observed.get("pseudo_evidence") != pseudo_evidence:
        raise ValueError("pseudo commit or ancestry mappings differ from cache")
    if observed.get("cases") != expected_cases:
        raise ValueError("row gates or sets differ from independent reconstruction")
    passed_rows = sum(case["gate"]["passed"] for case in expected_cases)
    expected_summary = {
        "row_count": 2,
        "projection_gate_passed": passed_rows,
        "projection_coverage": passed_rows / 2,
        "development_candidate_counts": {
            label: sum(case["gate"]["development_typing_candidate"] == label for case in expected_cases)
            for label in sorted({case["gate"]["development_typing_candidate"] for case in expected_cases})
        },
    }
    if observed.get("summary") != expected_summary:
        raise ValueError("summary differs from independent reconstruction")
    expected_advancement = {
        "minimum_projectable_rows": 2,
        "projectable_rows": passed_rows,
        "passed": passed_rows == 2,
        "status": (
            "advance_mattermost_release_graph_development_only"
            if passed_rows == 2 else "no_go_mattermost_release_graph_unstable"
        ),
        "independent_verification_required": True,
    }
    if observed.get("advancement_gate") != expected_advancement:
        raise ValueError("family advancement gate differs from reconstruction")
    boundary = observed.get("boundary") or {}
    for key in ("post_unsealing", "development_diagnostic_only"):
        if boundary.get(key) is not True:
            raise ValueError(f"boundary must keep {key}=true")
    for key in (
        "selection_uses_reviewer_labels", "label_is_human", "eligible_for_human_gold_claim",
        "accuracy_claim_allowed", "production_switch_allowed", "generalization_claim_allowed",
    ):
        if boundary.get(key) is not False:
            raise ValueError(f"boundary must keep {key}=false")
    return observed


def main() -> int:
    args = parse_args()
    manifest_path = resolve(args.manifest)
    analysis = validate(json.loads(manifest_path.read_text(encoding="utf-8")))
    print(
        "Verified Mattermost Git-tag graph: "
        f"{analysis['summary']['projection_gate_passed']}/2 projectable; "
        f"status={analysis['advancement_gate']['status']}; label_is_human=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
