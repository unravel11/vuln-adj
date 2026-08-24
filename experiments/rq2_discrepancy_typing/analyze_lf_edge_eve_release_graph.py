#!/usr/bin/env python3
"""Build the frozen LF Edge EVE release/LTS graph diagnostic."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "lf_edge_eve_release_graph_v1"
REMOTE_URL = "https://github.com/lf-edge/eve.git"
REPOSITORY_URL = "https://github.com/lf-edge/eve"
STRUCTURED_PACKAGE = "github.com/lf-edge/eve"
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
    "docs/annotation_guidelines/affected_versions_lf_edge_eve_release_graph_contract_v1.md"
)
DEFAULT_CACHE_DIR = "data/evidence_cache/rq2/lf_edge_eve_release_graph_v1"
DEFAULT_OUTPUT_DIR = (
    "results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "lf_edge_eve_release_graph_v1"
)
PSEUDO_PATTERN = re.compile(r"^(\d+\.\d+\.\d+)-(\d{14})-([0-9a-f]{12})$")

EXPECTED_PRODUCT_VERSIONS = tuple("""
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


def range_tuple(start: str | None, end: str | None) -> tuple:
    return ("range", start, start is not None, end, False)


CASE_SPECS = {
    "CVE-2023-43630": {
        "sample_id": "rq2_typing_holdout_v1:1179",
        "ghsa_id": "GHSA-phcg-h58r-gmcq",
        "pseudo": "0.0.0-20230126065759-d9383a7ee4e1",
        "nvd_span": range_tuple("9.0.0", "9.5.0"),
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
        "nvd_span": range_tuple("3.0.0", "9.5.0"),
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
    parser.add_argument("--worklist", default=DEFAULT_WORKLIST)
    parser.add_argument("--sealed-manifest", default=DEFAULT_SEALED_MANIFEST)
    parser.add_argument("--edge-audit", default=DEFAULT_EDGE_AUDIT)
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--timeout-seconds", type=int, default=60)
    parser.add_argument("--refresh", action="store_true")
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


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
        raise RuntimeError(
            f"git command failed ({completed.returncode}): {' '.join(command)}\n"
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


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


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
    spec = CASE_SPECS[cve_id]
    return (
        {"edge_virtualization_engine": [spec["nvd_span"]]},
        {STRUCTURED_PACKAGE: [range_tuple(None, spec["pseudo"])]},
    )


def load_fixed_rows(worklist: Path, sealed_manifest: Path, edge_audit: Path) -> list[dict]:
    sealed = json.loads(sealed_manifest.read_text(encoding="utf-8"))
    if file_sha256(worklist) != sealed["outputs"]["blind_worklist_d"]["sha256"]:
        raise ValueError("sealed worklist hash mismatch")
    audit = json.loads(edge_audit.read_text(encoding="utf-8"))
    family = next(
        (item for item in audit["family_ranking"] if item["project_family"] == "lf_edge_eve"),
        None,
    )
    if family is None or family.get("eligible_rank") != 2 or family.get("score") != 9:
        raise ValueError("parent edge audit LF Edge EVE ranking drift")
    expected_ids = {spec["sample_id"] for spec in CASE_SPECS.values()}
    rows = [row for row in load_jsonl(worklist) if row.get("sample_id") in expected_ids]
    if len(rows) != 2:
        raise ValueError(f"expected two LF Edge EVE rows, found {len(rows)}")
    for row in rows:
        spec = CASE_SPECS.get(row.get("cve_id"))
        if spec is None or row.get("sample_id") != spec["sample_id"]:
            raise ValueError(f"unexpected EVE row: {row.get('sample_id')}")
        expected_nvd, expected_ghsa = expected_claims(row["cve_id"])
        if claim_signature(row["nvd_value"]) != expected_nvd:
            raise ValueError(f"NVD claim drift for {row['cve_id']}")
        if claim_signature(row["ghsa_value"]) != expected_ghsa:
            raise ValueError(f"GHSA claim drift for {row['cve_id']}")
    return sorted(rows, key=lambda row: row["cve_id"])


def request_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "vuln-adj-eve-release-graph-v1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_or_load(
    cache_dir: Path,
    key: str,
    url: str,
    *,
    timeout_seconds: int,
    refresh: bool,
) -> tuple[bytes, dict]:
    body_path = cache_dir / f"{key}.response"
    metadata_path = cache_dir / f"{key}.fetch.json"
    if body_path.exists() and metadata_path.exists() and not refresh:
        body = body_path.read_bytes()
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        if metadata.get("url") != url or metadata.get("response_sha256") != sha256_bytes(body):
            raise ValueError(f"cached source binding mismatch for {key}")
        return body, metadata
    request = Request(url, headers=request_headers())
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            body = response.read()
            status = response.status
    except HTTPError as exc:
        body = exc.read()
        status = exc.code
    if status != 200:
        raise RuntimeError(f"required source {key} returned HTTP {status}")
    metadata = {
        "url": url,
        "http_status": status,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "response_sha256": sha256_bytes(body),
    }
    body_path.write_bytes(body)
    write_json(metadata_path, metadata)
    return body, metadata


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


def object_at(repo: Path, commit: str, path: str) -> str | None:
    raw = try_git(repo, "rev-parse", f"{commit}:{path}")
    return raw.decode("utf-8").strip() if raw is not None else None


def add_path_chain(repo: Path, objects: set[str], commit: str, path: str) -> None:
    root_tree = run_git(repo, "show", "-s", "--format=%T", commit).decode().strip()
    objects.add(root_tree)
    current = []
    for part in path.split("/"):
        current.append(part)
        oid = object_at(repo, commit, "/".join(current))
        if oid is None:
            break
        objects.add(oid)


def acquire_git_snapshot(cache_dir: Path, clone_dir: Path) -> tuple[Path, dict]:
    raw_refs = run_git(None, "ls-remote", "--tags", REMOTE_URL)
    refs = parse_refs(raw_refs)
    missing = [version for version in EXPECTED_PRODUCT_VERSIONS if version not in refs]
    if missing:
        raise ValueError(f"fixed EVE tags missing from official refs: {missing}")
    run_git(None, "clone", "--filter=blob:none", "--no-checkout", "--bare", REMOTE_URL, str(clone_dir))

    tag_map: dict[str, dict[str, str]] = {}
    for version in EXPECTED_PRODUCT_VERSIONS:
        ref = f"refs/tags/{version}"
        local_ref_oid = run_git(clone_dir, "rev-parse", ref).decode().strip()
        if local_ref_oid != refs[version]["ref_oid"]:
            raise ValueError(f"local and remote ref mismatch for {version}")
        commit_oid = run_git(clone_dir, "rev-parse", f"{ref}^{{commit}}").decode().strip()
        if refs[version]["peeled_oid"] not in {None, commit_oid}:
            raise ValueError(f"peeled tag mismatch for {version}")
        tag_map[version] = {"ref_oid": local_ref_oid, "commit_oid": commit_oid}

    pseudo_map: dict[str, dict[str, str]] = {}
    for cve_id, spec in CASE_SPECS.items():
        short_sha = PSEUDO_PATTERN.fullmatch(spec["pseudo"]).group(3)
        full_sha = run_git(clone_dir, "rev-parse", f"{short_sha}^{{commit}}").decode().strip()
        if not full_sha.startswith(short_sha):
            raise ValueError(f"pseudo commit prefix mismatch for {cve_id}")
        pseudo_map[cve_id] = {"short_sha": short_sha, "commit_oid": full_sha}

    tips = [item["commit_oid"] for item in tag_map.values()]
    tips.extend(item["commit_oid"] for item in pseudo_map.values())
    commit_ids = set(run_git(clone_dir, "rev-list", *tips).decode().splitlines())
    object_ids = set(commit_ids)
    object_ids.update(item["ref_oid"] for item in tag_map.values())
    object_ids.update(tips)
    materialized_commits = set(tips)
    for spec in CASE_SPECS.values():
        materialized_commits.update(tag_map[version]["commit_oid"] for version in spec["patched_anchors"])
    for commit in materialized_commits:
        for path in (
            "go.mod",
            "pkg/pillar/go.mod",
            "pkg/pillar/evetpm",
            "pkg/vtpm/build.yml",
            "pkg/vtpm",
        ):
            add_path_chain(clone_dir, object_ids, commit, path)

    object_list = ("\n".join(sorted(object_ids)) + "\n").encode()
    pack = run_git(clone_dir, "pack-objects", "--stdout", input_bytes=object_list)
    refs_path = cache_dir / "git_refs.txt"
    objects_path = cache_dir / "git_object_ids.txt"
    pack_path = cache_dir / "git_objects.pack"
    refs_path.write_bytes(raw_refs)
    objects_path.write_bytes(object_list)
    pack_path.write_bytes(pack)
    snapshot = {
        "schema_version": SCHEMA_VERSION,
        "remote_url": REMOTE_URL,
        "fixed_domain": list(EXPECTED_PRODUCT_VERSIONS),
        "tag_map": tag_map,
        "pseudo_map": pseudo_map,
        "reachable_commit_count": len(commit_ids),
        "packed_object_count": len(object_ids),
        "refs_sha256": sha256_bytes(raw_refs),
        "object_ids_sha256": sha256_bytes(object_list),
        "pack_sha256": sha256_bytes(pack),
    }
    write_json(cache_dir / "git_snapshot.json", snapshot)
    acquisition = {
        "schema_version": SCHEMA_VERSION,
        "remote_url": REMOTE_URL,
        "acquired_at": datetime.now(timezone.utc).isoformat(),
        "git_version": run_git(None, "--version").decode().strip(),
        "clone_filter": "blob:none",
        "tag_count": len(EXPECTED_PRODUCT_VERSIONS),
    }
    write_json(cache_dir / "git_acquisition.json", acquisition)
    return clone_dir, snapshot


def materialize_cached_pack(cache_dir: Path, repo: Path) -> dict:
    run_git(None, "init", "--bare", str(repo))
    pack = (cache_dir / "git_objects.pack").read_bytes()
    run_git(repo, "index-pack", "--stdin", input_bytes=pack)
    return json.loads((cache_dir / "git_snapshot.json").read_text(encoding="utf-8"))


@contextlib.contextmanager
def git_evidence_repository(cache_dir: Path, refresh: bool):
    required = [
        cache_dir / "git_refs.txt",
        cache_dir / "git_object_ids.txt",
        cache_dir / "git_objects.pack",
        cache_dir / "git_snapshot.json",
        cache_dir / "git_acquisition.json",
    ]
    with tempfile.TemporaryDirectory(prefix="eve-release-graph-") as temp:
        root = Path(temp)
        if not refresh and all(path.exists() for path in required):
            repo = root / "verified.git"
            snapshot = materialize_cached_pack(cache_dir, repo)
        else:
            repo = root / "source.git"
            repo, snapshot = acquire_git_snapshot(cache_dir, repo)
        yield repo, snapshot


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
        raise RuntimeError(completed.stderr.decode("utf-8", errors="replace"))
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


def version_in_span(version: str, span: tuple) -> bool:
    parsed = ProductVersion.parse(version).core
    _, start, start_inclusive, end, end_inclusive = span
    lower = ProductVersion.parse(start).core if start else None
    upper = ProductVersion.parse(end).core if end else None
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
    repo: Path,
    snapshot: dict,
    advisories: dict[str, dict],
    patches: dict[str, bytes],
) -> dict:
    tag_map = snapshot["tag_map"]
    object_snapshot_complete = all(
        try_git(repo, "cat-file", "-e", f"{item['commit_oid']}^{{commit}}") is not None
        for item in tag_map.values()
    )
    pseudo_evidence = {}
    cases = []
    for row in rows:
        cve_id = row["cve_id"]
        spec = CASE_SPECS[cve_id]
        binding = commit_binding(repo, cve_id, spec["pseudo"])
        pseudo_commit = binding["full_sha"]
        changed_paths = parse_patch_paths(patches[cve_id])
        facts = advisory_facts(advisories[cve_id])
        root_module = parse_module(show_path(repo, pseudo_commit, "go.mod"))
        owner_body = show_path(repo, pseudo_commit, spec["owner_manifest"])
        owner_module = parse_module(owner_body)
        component_exists = try_git(
            repo, "cat-file", "-e", f"{pseudo_commit}:{spec['component_path']}"
        ) is not None
        if spec["owner_module"] is None:
            owner_bound = bool(owner_body)
        else:
            owner_bound = owner_module == spec["owner_module"]

        comparisons = {}
        for version in EXPECTED_PRODUCT_VERSIONS:
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
                len(tag_map) == len(EXPECTED_PRODUCT_VERSIONS)
                and set(tag_map) == set(EXPECTED_PRODUCT_VERSIONS)
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
        relation = None
        candidate = "uncertain"
        if passed:
            nvd = {
                version for version in EXPECTED_PRODUCT_VERSIONS
                if version_in_span(version, spec["nvd_span"])
            }
            ghsa = {
                version for version, item in comparisons.items()
                if item["inside_exclusive_upper_pseudo_interval"] is True
            }
            relation = set_relation(nvd, ghsa)
            candidate = candidate_for_relation(relation)
            release_sets = {"nvd": sorted(nvd), "ghsa_pseudo_projection": sorted(ghsa)}
        cases.append({
            "schema_version": SCHEMA_VERSION,
            "sample_id": row["sample_id"],
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
            "release_set_relation": relation,
            "selection_uses_reviewer_labels": False,
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
        })

    passed_rows = sum(case["gate"]["passed"] for case in cases)
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "lf_edge_eve_release_graph_analysis",
        "product_release_domain": list(EXPECTED_PRODUCT_VERSIONS),
        "product_release_tags": tag_map,
        "git_snapshot": {
            "remote_url": snapshot["remote_url"],
            "reachable_commit_count": snapshot["reachable_commit_count"],
            "packed_object_count": snapshot["packed_object_count"],
            "refs_sha256": snapshot["refs_sha256"],
            "pack_sha256": snapshot["pack_sha256"],
        },
        "pseudo_evidence": pseudo_evidence,
        "cases": cases,
        "summary": {
            "row_count": len(cases),
            "projection_gate_passed": passed_rows,
            "projection_coverage": passed_rows / len(cases),
            "development_candidate_counts": {
                label: sum(case["gate"]["development_typing_candidate"] == label for case in cases)
                for label in sorted({case["gate"]["development_typing_candidate"] for case in cases})
            },
        },
        "advancement_gate": {
            "minimum_projectable_rows": 2,
            "projectable_rows": passed_rows,
            "passed": passed_rows == 2,
            "status": (
                "mechanism_pass_requires_new_blind_cohort"
                if passed_rows == 2 else "no_go_lf_edge_eve_release_graph_unstable"
            ),
            "candidate_promotion_allowed": False,
            "independent_verification_required": True,
        },
        "boundary": {
            "post_unsealing": True,
            "protocol_discovery_disclosed": True,
            "selection_uses_reviewer_labels": False,
            "development_diagnostic_only": True,
            "candidate_promotion_allowed": False,
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
            "accuracy_claim_allowed": False,
            "production_switch_allowed": False,
            "generalization_claim_allowed": False,
        },
    }


def render_markdown(analysis: dict) -> str:
    lines = [
        "# LF Edge EVE Release/LTS Graph v1",
        "",
        "> Post-unsealing mechanism diagnostic with disclosed protocol discovery; not human gold.",
        "",
        f"- Fixed product tags: `{len(analysis['product_release_domain'])}`",
        f"- Reachable commits in pack: `{analysis['git_snapshot']['reachable_commit_count']}`",
        f"- Projection gate passed: `{analysis['summary']['projection_gate_passed']}/2`",
        f"- Family status: `{analysis['advancement_gate']['status']}`",
        "",
        "| CVE | Gate | Ancestry counts | Failed checks | Relation | Candidate |",
        "|---|---|---|---|---|---|",
    ]
    for case in analysis["cases"]:
        counts = analysis["pseudo_evidence"][case["cve_id"]]["ancestry_counts"]
        count_text = ", ".join(f"{key}={value}" for key, value in counts.items())
        failed = ", ".join(case["gate"]["failed_checks"]) or "none"
        lines.append(
            f"| {case['cve_id']} | {str(case['gate']['passed']).lower()} | {count_text} | "
            f"{failed} | {case['release_set_relation'] or 'not computed'} | "
            f"{case['gate']['development_typing_candidate']} |"
        )
    lines.extend([
        "",
        "A repository coordinate is not promoted to a Go module identity. Diverged main/LTS",
        "histories and pseudo commits that do not touch the advisory component remain unresolved.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    worklist = resolve(args.worklist)
    sealed_manifest = resolve(args.sealed_manifest)
    edge_audit = resolve(args.edge_audit)
    contract = resolve(args.contract)
    cache_dir = resolve(args.cache_dir)
    output_dir = resolve(args.output_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = load_fixed_rows(worklist, sealed_manifest, edge_audit)

    advisories: dict[str, dict] = {}
    patches: dict[str, bytes] = {}
    for cve_id, spec in CASE_SPECS.items():
        key = cve_id.lower().replace("-", "_")
        advisory_body, _ = fetch_or_load(
            cache_dir,
            f"{key}_advisory",
            f"https://api.github.com/advisories/{spec['ghsa_id']}",
            timeout_seconds=args.timeout_seconds,
            refresh=args.refresh,
        )
        patch_body, _ = fetch_or_load(
            cache_dir,
            f"{key}_pseudo_patch",
            f"{REPOSITORY_URL}/commit/{PSEUDO_PATTERN.fullmatch(spec['pseudo']).group(3)}.patch",
            timeout_seconds=args.timeout_seconds,
            refresh=args.refresh,
        )
        advisories[cve_id] = json.loads(advisory_body)
        patches[cve_id] = patch_body

    with git_evidence_repository(cache_dir, args.refresh) as (repo, snapshot):
        analysis = analyze(rows, repo, snapshot, advisories, patches)

    analysis_path = output_dir / "analysis.json"
    summary_path = output_dir / "summary.md"
    write_json(analysis_path, analysis)
    summary_path.write_text(render_markdown(analysis), encoding="utf-8")
    cache_files = sorted(path for path in cache_dir.iterdir() if path.is_file())
    result_manifest = {
        "schema_version": SCHEMA_VERSION,
        "inputs": {
            "worklist": {"path": str(worklist), "sha256": file_sha256(worklist)},
            "sealed_manifest": {
                "path": str(sealed_manifest), "sha256": file_sha256(sealed_manifest)
            },
            "edge_audit": {"path": str(edge_audit), "sha256": file_sha256(edge_audit)},
            "contract": {"path": str(contract), "sha256": file_sha256(contract)},
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
        "release_count": len(EXPECTED_PRODUCT_VERSIONS),
        "projection_gate_passed": analysis["summary"]["projection_gate_passed"],
        "status": analysis["advancement_gate"]["status"],
        "output_dir": str(output_dir),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
