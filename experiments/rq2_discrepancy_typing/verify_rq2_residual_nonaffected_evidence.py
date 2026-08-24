#!/usr/bin/env python3
"""Independently verify the sealed RQ2 residual non-affected evidence diagnostic."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from html.parser import HTMLParser
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RESULT_MANIFEST = (
    "results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "residual_nonaffected_evidence_v1/manifest.json"
)
EXPECTED = {
    "rq2_typing_holdout_v1:1118": ("CVE-2024-8020", "cwe_ids"),
    "rq2_typing_holdout_v1:1023": ("CVE-2023-4304", "cwe_ids"),
    "rq2_typing_holdout_v1:787": ("CVE-2023-32187", "references"),
}
SUSE_REPAIR = re.compile(
    r"^(https://bugzilla\.suse\.com/show_bug\.cgi\?id=CVE-\d{4}-\d+)(?:https:/+)$"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=DEFAULT_RESULT_MANIFEST)
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


def checked(record: dict, name: str) -> Path:
    path = resolve(record["path"])
    if not path.is_file() or sha256(path) != record.get("sha256"):
        raise ValueError(f"missing or hash-mismatched {name}: {path}")
    return path


def load_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def projection(row: dict) -> dict:
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
    return {key: row[key] for key in allowed if key in row}


def reconstruct_worklist(source_path: Path, consensus_path: Path) -> list[dict]:
    selected = [
        row
        for row in load_jsonl(consensus_path)
        if row.get("secondary_strict_consensus") is False
        and row.get("field") != "affected_versions"
    ]
    identities = {
        row["sample_id"]: (row["cve_id"], row["field"])
        for row in selected
    }
    if identities != EXPECTED:
        raise ValueError(f"independent residual selection drift: {identities!r}")
    source = {row["sample_id"]: row for row in load_jsonl(source_path)}
    return [projection(source[sample_id]) for sample_id in sorted(EXPECTED)]


def load_evidence(seal: dict) -> dict[str, bytes]:
    result = {}
    for name, record in seal["evidence"].items():
        body = resolve(record["body_path"])
        metadata = resolve(record["metadata_path"])
        if not body.is_file() or sha256(body) != record["body_sha256"]:
            raise ValueError(f"evidence body drift: {name}")
        if not metadata.is_file() or sha256(metadata) != record["metadata_sha256"]:
            raise ValueError(f"evidence metadata drift: {name}")
        meta = json.loads(metadata.read_text(encoding="utf-8"))
        if (
            meta.get("requested_url") != record["url"]
            or meta.get("http_status") != 200
            or meta.get("body_sha256") != record["body_sha256"]
        ):
            raise ValueError(f"evidence metadata mismatch: {name}")
        result[name] = body.read_bytes()
    if len(result) != 12:
        raise ValueError(f"expected 12 evidence records, found {len(result)}")
    return result


def independent_lightning_gate(source: str) -> bool:
    tree = ast.parse(source)
    functions = [
        node
        for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "post_state"
    ]
    if len(functions) != 1:
        return False
    function = functions[0]
    route = any(
        isinstance(item, ast.Call)
        and isinstance(item.func, ast.Attribute)
        and item.func.attr == "post"
        and any(isinstance(arg, ast.Constant) and arg.value == "/api/v1/state" for arg in item.args)
        for item in function.decorator_list
    )
    state_access = any(
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Name)
        and node.value.id == "body"
        and isinstance(node.slice, ast.Constant)
        and node.slice.value == "state"
        for node in ast.walk(function)
    )
    request_json = any(
        isinstance(node, ast.Await)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Attribute)
        and node.value.func.attr == "json"
        for node in ast.walk(function)
    )
    return route and state_access and request_json and not any(
        isinstance(node, ast.Try) for node in ast.walk(function)
    )


def cwes(body: bytes) -> set[str]:
    payload = json.loads(body)
    return {item["cwe_id"] for item in payload.get("cwes", []) if item.get("cwe_id")}


class TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def compact(body: bytes) -> str:
    parser = TextExtractor()
    parser.feed(body.decode("utf-8", errors="replace"))
    visible = " ".join(" ".join(parser.parts).split()).lower()
    return re.sub(r"\s+:", ":", visible)


def relation(left: set[str], right: set[str]) -> str:
    if left == right:
        return "equal"
    if left < right:
        return "nvd_subset_of_ghsa"
    if right < left:
        return "ghsa_subset_of_nvd"
    if left & right:
        return "overlap_non_subset"
    return "disjoint"


def repaired(url: str) -> str:
    match = SUSE_REPAIR.fullmatch(url)
    return match.group(1) if match else url


def validate(result_manifest: dict) -> None:
    for key in (
        "candidate_promotion_allowed",
        "eligible_for_human_gold_claim",
        "label_is_human",
    ):
        if result_manifest.get(key) is not False:
            raise ValueError(f"result boundary drift: {key}")
    seal_path = checked(result_manifest["inputs"]["seal"], "result seal")
    checked(result_manifest["inputs"]["analyzer"], "result analyzer")
    analysis_path = checked(result_manifest["outputs"]["analysis"], "analysis")
    checked(result_manifest["outputs"]["summary"], "summary")
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    for key, expected in {
        "post_unsealing_targeted_diagnostic": True,
        "protocol_discovery_disclosed": True,
        "candidate_promotion_allowed": False,
        "eligible_for_human_gold_claim": False,
        "label_is_human": False,
    }.items():
        if seal.get(key) is not expected:
            raise ValueError(f"seal boundary drift: {key}")

    source_path = checked(seal["inputs"]["source"], "source")
    consensus_path = checked(seal["inputs"]["consensus"], "consensus")
    checked(seal["inputs"]["contract"], "contract")
    checked(seal["inputs"]["builder"], "builder")
    worklist_path = checked(seal["output"]["worklist"], "worklist")
    expected_worklist = reconstruct_worklist(source_path, consensus_path)
    if load_jsonl(worklist_path) != expected_worklist:
        raise ValueError("sealed worklist differs from independent reconstruction")

    evidence = load_evidence(seal)
    rows = {row["cve_id"]: row for row in expected_worklist}
    if not independent_lightning_gate(evidence["lightning_api_source"].decode("utf-8")):
        raise ValueError("independent Lightning source gate failed")
    if "CWE-248" not in cwes(evidence["lightning_advisory"]):
        raise ValueError("Lightning advisory CWE drift")
    if not all(
        marker in compact(evidence["cwe_248"])
        for marker in ("cwe-248: uncaught exception", "exception is thrown", "not caught")
    ):
        raise ValueError("CWE-248 definition drift")
    if not all(
        marker in compact(evidence["cwe_400"])
        for marker in (
            "cwe-400: uncontrolled resource consumption",
            "allocation and maintenance of a limited resource",
        )
    ):
        raise ValueError("CWE-400 definition drift")

    cwe840 = compact(evidence["cwe_840"])
    if not all(
        marker in cwe840
        for marker in (
            "cwe category: business logic errors",
            "vulnerability mapping: prohibited",
            "must not be used to map to real-world vulnerabilities",
        )
    ):
        raise ValueError("CWE-840 mapping gate drift")
    patch_added = [
        line[1:]
        for line in evidence["froxlor_patch"].decode("utf-8").splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]
    patch_text = "\n".join(patch_added)
    if not all(
        marker in patch_text
        for marker in ("empty(trim($name))", "empty(trim($email))", "stringisempty")
    ):
        raise ValueError("Froxlor validation patch drift")
    if any(
        marker in patch_text.lower()
        for marker in ("authorization", "authorize", "permission", "access control")
    ):
        raise ValueError("Froxlor patch now establishes authorization semantics")
    if not {"CWE-284", "CWE-862"}.issubset(cwes(evidence["froxlor_advisory"])):
        raise ValueError("Froxlor advisory CWE drift")

    for name in ("suse_malformed_single_slash", "suse_malformed_double_slash"):
        text = compact(evidence[name])
        if "invalid bug id" not in text or "is not a valid bug number nor an alias" not in text:
            raise ValueError(f"SUSE malformed resource drift: {name}")
    k3s = rows["CVE-2023-32187"]
    exact = relation(set(k3s["nvd_value"]), set(k3s["ghsa_value"]))
    repaired_relation = relation(
        {repaired(url) for url in k3s["nvd_value"]},
        {repaired(url) for url in k3s["ghsa_value"]},
    )
    if exact != "overlap_non_subset" or repaired_relation != "nvd_subset_of_ghsa":
        raise ValueError("K3s profile relation drift")

    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    cases = {case["cve_id"]: case for case in analysis["cases"]}
    expected_candidates = {
        "CVE-2024-8020": "factual_conflict",
        "CVE-2023-4304": "uncertain",
        "CVE-2023-32187": "uncertain",
    }
    if set(cases) != set(expected_candidates):
        raise ValueError("analysis case set drift")
    for cve_id, candidate in expected_candidates.items():
        case = cases[cve_id]
        if case.get("development_typing_candidate") != candidate:
            raise ValueError(f"candidate drift for {cve_id}")
        if (
            case.get("promoted_candidate") is not None
            or case.get("candidate_promotion_allowed") is not False
            or case.get("label_is_human") is not False
        ):
            raise ValueError(f"advancement boundary drift for {cve_id}")
    if analysis.get("summary") != {
        "row_count": 3,
        "development_candidate_counts": {"factual_conflict": 1, "uncertain": 2},
        "promoted_candidate_count": 0,
        "mechanism_supported_rows": 1,
        "construct_unresolved_rows": 2,
        "original_rq2_combined_candidate_unchanged": "1219/1250",
        "status": "targeted_residual_diagnostic_no_promotion",
    }:
        raise ValueError("analysis summary drift")


def main() -> int:
    args = parse_args()
    manifest_path = resolve(args.manifest)
    validate(json.loads(manifest_path.read_text(encoding="utf-8")))
    print("Verified residual non-affected evidence: 1/3 development candidate; promotion disabled")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
