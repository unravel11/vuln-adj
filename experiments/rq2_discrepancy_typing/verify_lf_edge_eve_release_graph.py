#!/usr/bin/env python3
"""Independently verify the cached LF Edge EVE release/LTS graph."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
AUTHORITATIVE_PROJECT_ROOT = Path("/home/xiaoyuliang/code/vuln-adj")
SCHEMA_VERSION = "lf_edge_eve_release_graph_v1"
REMOTE_URL = "https://github.com/lf-edge/eve.git"
REPOSITORY_URL = "https://github.com/lf-edge/eve"
STRUCTURED_PACKAGE = "github.com/lf-edge/eve"
DEFAULT_MANIFEST = (
    "results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "lf_edge_eve_release_graph_v1/manifest.json"
)
PSEUDO_PATTERN = re.compile(r"^(\d+\.\d+\.\d+)-(\d{14})-([0-9a-f]{12})$")
VERSIONS = tuple("""
3.0.0 3.0.1 3.1.0 3.1.1 3.2.0 3.3.0 3.3.1 3.3.2 3.4.0 3.4.1 3.4.2
3.4.10 3.5.0 3.6.0 3.7.0 3.8.0 3.8.1 3.8.2 3.9.0 3.9.1 3.9.2 3.9.3
3.10.0 4.1.0 4.1.1 4.1.2 4.2.0 4.3.0 4.3.1 4.5.0 4.5.1 4.5.2 4.6.0
4.7.0 4.7.1 4.8.0 4.8.1 4.8.2 4.8.4 4.9.0 4.9.1 4.10.0 5.0.0 5.0.1
5.1.0 5.1.1 5.1.10 5.1.11 5.2.0 5.2.1 5.2.2 5.2.3 5.2.4 5.3.0 5.4.0
5.4.1 5.5.0 5.6.0 5.6.1 5.6.2 5.6.3 5.7.0 5.7.1 5.8.0 5.8.1 5.8.2
5.9.0 5.10.0 5.10.1 5.10.2 5.10.3 5.10.4 5.12.0 5.12.1 5.12.2 5.12.3
5.12.4 5.12.5 5.12.6 5.12.7 5.12.8 5.12.9 5.14.0 5.15.0 5.15.1 5.15.2
5.16.0 5.16.1 5.17.0 5.18.0 5.18.1 5.19.0 5.20.0 5.20.1 5.21.0 5.21.1
5.21.2 5.21.3 5.21.4 5.21.5 5.21.6 5.21.7 5.21.8 6.0.0 6.1.0 6.1.1 6.1.2
6.2.0 6.3.0 6.4.0 6.5.0 6.6.0 6.6.1 6.6.2 6.6.3 6.7.0 6.8.0 6.8.1
6.8.2 6.8.3 6.8.4 6.8.5 6.9.0 6.10.0 6.11.0 6.12.0 6.12.1 6.12.2
6.12.3 6.12.4 6.13.0 6.14.0 7.0.0 7.1.0 7.2.0 7.3.0 7.4.0 7.4.1 7.5.0
7.6.0 7.7.0 7.8.0 7.9.0 7.9.1 7.9.2 7.10.0 7.11.0 8.0.0 8.1.0 8.2.0
8.3.0 8.3.1 8.4.0 8.5.0 8.5.1 8.5.2 8.5.3 8.5.4 8.6.0 8.7.0 8.8.0
8.9.0 8.9.1 8.10.0 8.11.0 8.11.1 8.12.0 8.12.1-lts 8.12.2-lts 8.12.3-lts
8.12.4-lts 8.12.5-lts 9.0.0 9.0.1 9.1.0 9.1.1 9.2.0 9.3.0 9.3.1 9.4.0
9.4.1 9.4.2 9.4.3-lts 9.4.4-lts 9.4.5-lts 9.4.6-lts 9.4.7-lts 9.4.8-lts
9.4.9-lts 9.4.10-lts 9.4.11-lts 9.4.12-lts 9.4.13-lts 9.4.14-lts
9.4.15-lts 9.4.16-lts 9.4.17-lts 9.5.0 9.6.0 9.7.0 9.8.0 9.9.0 9.10.0
9.11.0 9.12.0 10.0.0 10.1.0
""".split())


def span(start: str | None, end: str | None) -> tuple:
    return ("range", start, start is not None, end, False)


SPECS = {
    "CVE-2023-43630": {
        "sample_id": "rq2_typing_holdout_v1:1179",
        "ghsa_id": "GHSA-phcg-h58r-gmcq",
        "pseudo": "0.0.0-20230126065759-d9383a7ee4e1",
        "nvd_span": span("9.0.0", "9.5.0"),
        "component_path": "pkg/pillar/evetpm",
        "owner_manifest": "pkg/pillar/go.mod",
        "owner_module": "github.com/lf-edge/eve/pkg/pillar",
        "advisory_package": "github.com/lf-edge/eve/pkg/pillar/evetpm",
        "patched_anchors": ("9.4.3-lts", "9.5.0"),
    },
    "CVE-2023-43632": {
        "sample_id": "rq2_typing_holdout_v1:130",
        "ghsa_id": "GHSA-6jp5-grgh-jw42",
        "pseudo": "0.0.0-20230519072751-977f42b07fa9",
        "nvd_span": span("3.0.0", "9.5.0"),
        "component_path": "pkg/vtpm",
        "owner_manifest": "pkg/vtpm/build.yml",
        "owner_module": None,
        "advisory_package": "github.com/lf-edge/eve/pkg/vtpm",
        "patched_anchors": ("9.4.3-lts", "10.1.0"),
    },
}


@dataclass(frozen=True, order=True)
class ProductVersion:
    major: int
    minor: int
    patch: int
    lts: bool

    @classmethod
    def parse(cls, raw: str) -> "ProductVersion":
        match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(-lts)?", raw)
        if match is None:
            raise ValueError(f"unsupported EVE release token: {raw}")
        return cls(*(int(value) for value in match.groups()[:3]), bool(match.group(4)))

    @property
    def core(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    if not path.is_absolute():
        return (PROJECT_ROOT / path).resolve()
    if path.exists():
        return path
    try:
        relative = path.relative_to(AUTHORITATIVE_PROJECT_ROOT)
    except ValueError:
        return path
    return (PROJECT_ROOT / relative).resolve()


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verified_record(record: dict, name: str) -> Path:
    path = resolve(record["path"])
    if not path.is_file():
        raise ValueError(f"{name} is missing: {path}")
    if file_sha256(path) != record.get("sha256"):
        raise ValueError(f"{name} hash mismatch")
    return path


def run_git(repo: Path | None, *args: str, input_bytes: bytes | None = None) -> bytes:
    command = ["git"]
    if repo is not None:
        command.extend(["-C", str(repo)])
    command.extend(args)
    completed = subprocess.run(
        command,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError(
            f"git verification command failed: {' '.join(command)}\n"
            f"{completed.stderr.decode('utf-8', errors='replace')}"
        )
    return completed.stdout


def try_git(repo: Path, *args: str) -> bytes | None:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return completed.stdout if completed.returncode == 0 else None


def parse_refs(raw: bytes) -> dict[str, dict[str, str | None]]:
    refs: dict[str, dict[str, str | None]] = {}
    for line in raw.decode("utf-8").splitlines():
        oid, ref = line.split("\t", 1)
        if not ref.startswith("refs/tags/"):
            continue
        name = ref.removeprefix("refs/tags/")
        if name.endswith("^{}"):
            refs.setdefault(name[:-3], {"ref_oid": None, "peeled_oid": None})["peeled_oid"] = oid
        else:
            refs.setdefault(name, {"ref_oid": None, "peeled_oid": None})["ref_oid"] = oid
    return refs


def metadata_bound(cache: dict[str, Path], key: str, expected_url: str) -> bytes:
    body = cache[f"{key}.response"].read_bytes()
    metadata = json.loads(cache[f"{key}.fetch.json"].read_text(encoding="utf-8"))
    if metadata.get("url") != expected_url or metadata.get("http_status") != 200:
        raise ValueError(f"source metadata mismatch for {key}")
    if metadata.get("response_sha256") != hashlib.sha256(body).hexdigest():
        raise ValueError(f"source response hash mismatch for {key}")
    return body


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


def parse_module(body: bytes | None) -> str | None:
    if body is None:
        return None
    match = re.search(rb"(?m)^module\s+(\S+)\s*$", body)
    return match.group(1).decode() if match else None


def show_path(repo: Path, commit: str, path: str) -> bytes | None:
    return try_git(repo, "show", f"{commit}:{path}")


def parse_patch_paths(body: bytes) -> list[str]:
    return sorted(set(re.findall(r"(?m)^diff --git a/(.+?) b/", body.decode("utf-8"))))


def commit_binding(repo: Path, cve_id: str, pseudo: str) -> dict:
    match = PSEUDO_PATTERN.fullmatch(pseudo)
    if match is None:
        raise ValueError(f"invalid pseudo version for {cve_id}")
    _, timestamp, short_sha = match.groups()
    full_sha = run_git(repo, "rev-parse", f"{short_sha}^{{commit}}").decode().strip()
    commit_body = run_git(repo, "cat-file", "commit", full_sha).decode("utf-8")
    committer_line = next(
        (line for line in commit_body.splitlines() if line.startswith("committer ")),
        None,
    )
    if committer_line is None:
        raise ValueError(f"commit object lacks committer line for {cve_id}")
    epoch = int(committer_line.rsplit(" ", 2)[-2])
    observed_time = datetime.fromtimestamp(epoch, timezone.utc)
    observed = observed_time.isoformat().replace("+00:00", "Z")
    expected = datetime.strptime(timestamp, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    checks = {
        "sha_prefix_matches": full_sha.startswith(short_sha),
        "committer_timestamp_matches": observed_time == expected,
    }
    return {
        "cve_id": cve_id,
        "pseudo_version": pseudo,
        "short_sha": short_sha,
        "full_sha": full_sha,
        "expected_committer_timestamp": expected.isoformat().replace("+00:00", "Z"),
        "observed_committer_timestamp": observed,
        "checks": checks,
        "bound": all(checks.values()),
    }


def is_ancestor(repo: Path, ancestor: str, descendant: str) -> bool:
    completed = subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", ancestor, descendant],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode not in {0, 1}:
        raise ValueError(completed.stderr.decode("utf-8", errors="replace"))
    return completed.returncode == 0


def ancestry_status(repo: Path, tag_commit: str, pseudo_commit: str) -> str:
    if tag_commit == pseudo_commit:
        return "identical"
    if is_ancestor(repo, tag_commit, pseudo_commit):
        return "ahead"
    if is_ancestor(repo, pseudo_commit, tag_commit):
        return "behind"
    return "diverged"


def ancestry_membership(status: str) -> bool | None:
    if status == "ahead":
        return True
    if status in {"behind", "identical"}:
        return False
    return None


def normalize_package(value: str) -> str:
    return value.strip().rstrip("/")


def advisory_facts(document: dict) -> dict:
    vulnerabilities = document.get("vulnerabilities") or []
    packages = sorted({
        normalize_package(str((item.get("package") or {}).get("name") or ""))
        for item in vulnerabilities
        if (item.get("package") or {}).get("name")
    })
    patched = sorted({
        str(item.get("first_patched_version") or "")
        for item in vulnerabilities
        if item.get("first_patched_version")
    })
    return {
        "ghsa_id": document.get("ghsa_id"),
        "cve_id": document.get("cve_id"),
        "source_code_location": document.get("source_code_location"),
        "packages": packages,
        "first_patched_versions": patched,
    }


def version_in_span(version: str, claim_span: tuple) -> bool:
    parsed = ProductVersion.parse(version).core
    _, start, start_inclusive, end, end_inclusive = claim_span
    lower = ProductVersion.parse(start).core if start else None
    upper = ProductVersion.parse(end).core if end else None
    if lower is not None and (parsed < lower or (parsed == lower and not start_inclusive)):
        return False
    if upper is not None and (parsed > upper or (parsed == upper and not end_inclusive)):
        return False
    return True


def relation(nvd: set[str], ghsa: set[str]) -> str:
    if nvd == ghsa:
        return "equal"
    if nvd < ghsa:
        return "nvd_subset_of_ghsa"
    if ghsa < nvd:
        return "ghsa_subset_of_nvd"
    if nvd & ghsa:
        return "overlap"
    return "disjoint"


def relation_candidate(value: str) -> str:
    if value == "equal":
        return "representation_discrepancy"
    if value in {"nvd_subset_of_ghsa", "ghsa_subset_of_nvd"}:
        return "incomplete"
    return "factual_conflict"


def validate(manifest: dict) -> dict:
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unexpected manifest schema")
    inputs = {
        name: verified_record(record, f"input:{name}")
        for name, record in manifest["inputs"].items()
    }
    analysis_path = verified_record(manifest["outputs"]["analysis.json"], "output:analysis")
    verified_record(manifest["outputs"]["summary.md"], "output:summary")
    cache = {
        name: verified_record(record, f"cache:{name}")
        for name, record in manifest["evidence_cache"].items()
    }
    expected_cache = {
        "git_refs.txt", "git_object_ids.txt", "git_objects.pack", "git_snapshot.json",
        "git_acquisition.json",
    }
    for cve_id in SPECS:
        key = cve_id.lower().replace("-", "_")
        expected_cache.update({
            f"{key}_advisory.response", f"{key}_advisory.fetch.json",
            f"{key}_pseudo_patch.response", f"{key}_pseudo_patch.fetch.json",
        })
    if set(cache) != expected_cache:
        raise ValueError("evidence cache inventory differs from fixed v1 contract")

    sealed = json.loads(inputs["sealed_manifest"].read_text(encoding="utf-8"))
    if sealed["outputs"]["blind_worklist_d"]["sha256"] != file_sha256(inputs["worklist"]):
        raise ValueError("worklist seal mismatch")
    audit = json.loads(inputs["edge_audit"].read_text(encoding="utf-8"))
    family = next(
        (item for item in audit["family_ranking"] if item["project_family"] == "lf_edge_eve"),
        None,
    )
    if family is None or family.get("eligible_rank") != 2 or family.get("score") != 9:
        raise ValueError("edge audit LF Edge EVE ranking drift")
    rows = {
        row["cve_id"]: row
        for row in (
            json.loads(line) for line in inputs["worklist"].read_text(encoding="utf-8").splitlines()
            if line
        )
        if row.get("cve_id") in SPECS
    }
    if set(rows) != set(SPECS):
        raise ValueError("fixed LF Edge EVE rows are missing")
    for cve_id, spec in SPECS.items():
        row = rows[cve_id]
        if row.get("sample_id") != spec["sample_id"] or row.get("field") != "affected_versions":
            raise ValueError(f"fixed row identity drift for {cve_id}")
        if claim_signature(row["nvd_value"]) != {"edge_virtualization_engine": [spec["nvd_span"]]}:
            raise ValueError(f"NVD claim drift for {cve_id}")
        if claim_signature(row["ghsa_value"]) != {
            STRUCTURED_PACKAGE: [span(None, spec["pseudo"])]
        }:
            raise ValueError(f"GHSA claim drift for {cve_id}")

    refs_raw = cache["git_refs.txt"].read_bytes()
    object_ids_raw = cache["git_object_ids.txt"].read_bytes()
    pack = cache["git_objects.pack"].read_bytes()
    snapshot = json.loads(cache["git_snapshot.json"].read_text(encoding="utf-8"))
    acquisition = json.loads(cache["git_acquisition.json"].read_text(encoding="utf-8"))
    if snapshot.get("schema_version") != SCHEMA_VERSION or snapshot.get("remote_url") != REMOTE_URL:
        raise ValueError("Git snapshot identity mismatch")
    if snapshot.get("fixed_domain") != list(VERSIONS):
        raise ValueError("Git snapshot domain drift")
    if snapshot.get("refs_sha256") != hashlib.sha256(refs_raw).hexdigest():
        raise ValueError("Git refs hash mismatch")
    if snapshot.get("object_ids_sha256") != hashlib.sha256(object_ids_raw).hexdigest():
        raise ValueError("Git object list hash mismatch")
    if snapshot.get("pack_sha256") != hashlib.sha256(pack).hexdigest():
        raise ValueError("Git pack hash mismatch")
    if acquisition.get("remote_url") != REMOTE_URL or acquisition.get("tag_count") != 207:
        raise ValueError("Git acquisition metadata mismatch")

    refs = parse_refs(refs_raw)
    missing = [version for version in VERSIONS if version not in refs]
    if missing:
        raise ValueError(f"fixed tags missing from refs: {missing}")
    advisories = {}
    patches = {}
    for cve_id, spec in SPECS.items():
        key = cve_id.lower().replace("-", "_")
        advisories[cve_id] = json.loads(metadata_bound(
            cache,
            f"{key}_advisory",
            f"https://api.github.com/advisories/{spec['ghsa_id']}",
        ))
        short_sha = PSEUDO_PATTERN.fullmatch(spec["pseudo"]).group(3)
        patches[cve_id] = metadata_bound(
            cache,
            f"{key}_pseudo_patch",
            f"{REPOSITORY_URL}/commit/{short_sha}.patch",
        )

    with tempfile.TemporaryDirectory(prefix="verify-eve-release-graph-") as temp:
        repo = Path(temp) / "objects.git"
        run_git(None, "init", "--bare", str(repo))
        run_git(repo, "index-pack", "--stdin", input_bytes=pack)
        object_ids = [line for line in object_ids_raw.decode().splitlines() if line]
        if len(object_ids) != snapshot.get("packed_object_count") or len(set(object_ids)) != len(object_ids):
            raise ValueError("packed object inventory count mismatch")
        for oid in object_ids:
            if try_git(repo, "cat-file", "-e", oid) is None:
                raise ValueError(f"packed object missing: {oid}")
        tag_map = snapshot["tag_map"]
        if len(tag_map) != len(VERSIONS) or set(tag_map) != set(VERSIONS):
            raise ValueError("tag map domain drift")
        for version in VERSIONS:
            record = tag_map[version]
            if record["ref_oid"] != refs[version]["ref_oid"]:
                raise ValueError(f"official ref binding mismatch for {version}")
            peeled = run_git(repo, "rev-parse", f"{record['ref_oid']}^{{commit}}").decode().strip()
            if peeled != record["commit_oid"] or refs[version]["peeled_oid"] not in {None, peeled}:
                raise ValueError(f"tag commit binding mismatch for {version}")
        tips = [record["commit_oid"] for record in tag_map.values()]
        tips.extend(record["commit_oid"] for record in snapshot["pseudo_map"].values())
        reachable = set(run_git(repo, "rev-list", *tips).decode().splitlines())
        if len(reachable) != snapshot.get("reachable_commit_count"):
            raise ValueError("reachable commit count mismatch")

        object_snapshot_complete = all(
            try_git(repo, "cat-file", "-e", f"{item['commit_oid']}^{{commit}}") is not None
            for item in tag_map.values()
        )
        pseudo_evidence = {}
        expected_cases = []
        for cve_id in sorted(SPECS):
            spec = SPECS[cve_id]
            binding = commit_binding(repo, cve_id, spec["pseudo"])
            pseudo_commit = binding["full_sha"]
            if snapshot["pseudo_map"][cve_id]["commit_oid"] != pseudo_commit:
                raise ValueError(f"pseudo map mismatch for {cve_id}")
            changed_paths = parse_patch_paths(patches[cve_id])
            facts = advisory_facts(advisories[cve_id])
            root_module = parse_module(show_path(repo, pseudo_commit, "go.mod"))
            owner_body = show_path(repo, pseudo_commit, spec["owner_manifest"])
            owner_module = parse_module(owner_body)
            component_exists = try_git(
                repo, "cat-file", "-e", f"{pseudo_commit}:{spec['component_path']}"
            ) is not None
            owner_bound = bool(owner_body) if spec["owner_module"] is None else (
                owner_module == spec["owner_module"]
            )
            comparisons = {}
            for version in VERSIONS:
                status = ancestry_status(repo, tag_map[version]["commit_oid"], pseudo_commit)
                comparisons[version] = {
                    "status": status,
                    "inside_exclusive_upper_pseudo_interval": ancestry_membership(status),
                }
            ancestry_total = all(
                item["inside_exclusive_upper_pseudo_interval"] is not None
                for item in comparisons.values()
            )
            anchor_checks = {}
            for version in spec["patched_anchors"]:
                status = comparisons[version]["status"]
                anchor_checks[version] = {
                    "declared_by_current_advisory": version in facts["first_patched_versions"],
                    "contains_pseudo_commit": status in {"behind", "identical"},
                    "status": status,
                }
            advisory_package_bound = normalize_package(spec["advisory_package"]) in facts["packages"]
            repository_bound = (
                facts["ghsa_id"] == spec["ghsa_id"]
                and facts["cve_id"] == cve_id
                and str(facts["source_code_location"] or "").rstrip("/") == REPOSITORY_URL
            )
            component_coherent = any(
                path == spec["component_path"] or path.startswith(spec["component_path"] + "/")
                for path in changed_paths
            )
            pseudo_evidence[cve_id] = {
                "commit": binding,
                "changed_paths": changed_paths,
                "root_module_identity": root_module,
                "owner_manifest": spec["owner_manifest"],
                "owner_module_identity": owner_module,
                "advisory": facts,
                "comparisons": comparisons,
                "ancestry_counts": {
                    status: sum(item["status"] == status for item in comparisons.values())
                    for status in ("ahead", "behind", "identical", "diverged")
                },
                "ancestry_total": ancestry_total,
                "patched_anchor_checks": anchor_checks,
            }
            checks = {
                "fixed_input_signature": True,
                "product_release_domain_complete": (
                    len(tag_map) == len(VERSIONS) and set(tag_map) == set(VERSIONS)
                ),
                "git_object_snapshot_complete": object_snapshot_complete,
                "cve_repository_binding": repository_bound,
                "pseudo_commit_bound": binding["bound"],
                "structured_root_module_identity_bound": root_module == STRUCTURED_PACKAGE,
                "advisory_component_identity_bound": (
                    advisory_package_bound and component_exists and owner_bound
                ),
                "pseudo_component_path_coherent": component_coherent,
                "pseudo_ancestry_total": ancestry_total,
                "patched_anchor_ancestry_bound": all(
                    value["declared_by_current_advisory"] and value["contains_pseudo_commit"]
                    for value in anchor_checks.values()
                ),
            }
            passed = all(checks.values())
            release_sets = None
            set_value = None
            candidate = "uncertain"
            if passed:
                nvd = {version for version in VERSIONS if version_in_span(version, spec["nvd_span"])}
                ghsa = {
                    version for version, item in comparisons.items()
                    if item["inside_exclusive_upper_pseudo_interval"] is True
                }
                set_value = relation(nvd, ghsa)
                candidate = relation_candidate(set_value)
                release_sets = {"nvd": sorted(nvd), "ghsa_pseudo_projection": sorted(ghsa)}
            expected_cases.append({
                "schema_version": SCHEMA_VERSION,
                "sample_id": spec["sample_id"],
                "cve_id": cve_id,
                "checks": checks,
                "gate": {
                    "passed": passed,
                    "status": (
                        "eve_release_projection_allowed_mechanism_only"
                        if passed else "abstain_eve_release_projection_unresolved"
                    ),
                    "failed_checks": [name for name, value in checks.items() if not value],
                    "development_typing_candidate": candidate,
                    "candidate_promotion_allowed": False,
                    "label_is_human": False,
                    "eligible_for_human_gold_claim": False,
                },
                "release_sets": release_sets,
                "release_set_relation": set_value,
                "selection_uses_reviewer_labels": False,
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
            })

    observed = json.loads(analysis_path.read_text(encoding="utf-8"))
    expected_git_snapshot = {
        "remote_url": snapshot["remote_url"],
        "reachable_commit_count": snapshot["reachable_commit_count"],
        "packed_object_count": snapshot["packed_object_count"],
        "refs_sha256": snapshot["refs_sha256"],
        "pack_sha256": snapshot["pack_sha256"],
    }
    if observed.get("product_release_domain") != list(VERSIONS):
        raise ValueError("observed release domain drift")
    if observed.get("product_release_tags") != snapshot["tag_map"]:
        raise ValueError("observed tag map differs from verified refs")
    if observed.get("git_snapshot") != expected_git_snapshot:
        raise ValueError("observed Git snapshot summary differs")
    if observed.get("pseudo_evidence") != pseudo_evidence:
        raise ValueError("pseudo evidence differs from independent reconstruction")
    if observed.get("cases") != expected_cases:
        raise ValueError("row gates or release sets differ from reconstruction")
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
        raise ValueError("summary differs from reconstruction")
    expected_advancement = {
        "minimum_projectable_rows": 2,
        "projectable_rows": passed_rows,
        "passed": passed_rows == 2,
        "status": (
            "mechanism_pass_requires_new_blind_cohort"
            if passed_rows == 2 else "no_go_lf_edge_eve_release_graph_unstable"
        ),
        "candidate_promotion_allowed": False,
        "independent_verification_required": True,
    }
    if observed.get("advancement_gate") != expected_advancement:
        raise ValueError("family advancement gate differs")
    boundary = observed.get("boundary") or {}
    for key in ("post_unsealing", "protocol_discovery_disclosed", "development_diagnostic_only"):
        if boundary.get(key) is not True:
            raise ValueError(f"boundary must keep {key}=true")
    for key in (
        "selection_uses_reviewer_labels", "candidate_promotion_allowed", "label_is_human",
        "eligible_for_human_gold_claim", "accuracy_claim_allowed", "production_switch_allowed",
        "generalization_claim_allowed",
    ):
        if boundary.get(key) is not False:
            raise ValueError(f"boundary must keep {key}=false")
    return observed


def main() -> int:
    args = parse_args()
    manifest_path = resolve(args.manifest)
    analysis = validate(json.loads(manifest_path.read_text(encoding="utf-8")))
    print(
        "Verified LF Edge EVE release/LTS graph: "
        f"{analysis['summary']['projection_gate_passed']}/2 projectable; "
        f"status={analysis['advancement_gate']['status']}; label_is_human=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
