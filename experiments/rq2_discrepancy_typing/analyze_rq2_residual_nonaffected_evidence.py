#!/usr/bin/env python3
"""Analyze the sealed three-row RQ2 residual evidence diagnostic without network access."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "rq2_residual_nonaffected_evidence_v1"
DEFAULT_SEAL = (
    "data/annotations/holdout/rq2_typing_v1/tiebreak_v1/"
    "residual_nonaffected_evidence_v1/manifest.sealed.json"
)
DEFAULT_OUTPUT_DIR = (
    "results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "residual_nonaffected_evidence_v1"
)
EXPECTED_SAMPLE_IDS = {
    "rq2_typing_holdout_v1:1118",
    "rq2_typing_holdout_v1:1023",
    "rq2_typing_holdout_v1:787",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seal", default=DEFAULT_SEAL)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def portable_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path.resolve())


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


def verified_path(record: dict, name: str) -> Path:
    path = resolve(record["path"])
    if not path.is_file() or sha256(path) != record.get("sha256"):
        raise ValueError(f"missing or hash-mismatched {name}: {path}")
    return path


def evidence_body(record: dict, name: str) -> bytes:
    body_path = resolve(record["body_path"])
    metadata_path = resolve(record["metadata_path"])
    if not body_path.is_file() or sha256(body_path) != record.get("body_sha256"):
        raise ValueError(f"evidence body drift for {name}")
    if not metadata_path.is_file() or sha256(metadata_path) != record.get("metadata_sha256"):
        raise ValueError(f"evidence metadata drift for {name}")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if metadata.get("requested_url") != record.get("url"):
        raise ValueError(f"evidence URL drift for {name}")
    if metadata.get("http_status") != 200:
        raise ValueError(f"non-success evidence status for {name}")
    if metadata.get("body_sha256") != record.get("body_sha256"):
        raise ValueError(f"metadata body hash drift for {name}")
    return body_path.read_bytes()


def advisory_cwes(body: bytes) -> set[str]:
    payload = json.loads(body)
    return {str(item.get("cwe_id")) for item in payload.get("cwes", []) if item.get("cwe_id")}


def lightning_source_gate(source: str) -> dict:
    tree = ast.parse(source)
    function = next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "post_state"
        ),
        None,
    )
    if function is None:
        return {
            "handler_found": False,
            "post_route_bound": False,
            "request_json_parsed": False,
            "direct_state_subscript": False,
            "local_try_present": False,
            "passed": False,
        }
    route_bound = any(
        isinstance(decorator, ast.Call)
        and isinstance(decorator.func, ast.Attribute)
        and decorator.func.attr == "post"
        and any(
            isinstance(arg, ast.Constant) and arg.value == "/api/v1/state"
            for arg in decorator.args
        )
        for decorator in function.decorator_list
    )
    request_json = any(
        isinstance(node, ast.Await)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Attribute)
        and isinstance(node.value.func.value, ast.Name)
        and node.value.func.value.id == "request"
        and node.value.func.attr == "json"
        for node in ast.walk(function)
    )
    direct_state = any(
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Name)
        and node.value.id == "body"
        and isinstance(node.slice, ast.Constant)
        and node.slice.value == "state"
        for node in ast.walk(function)
    )
    local_try = any(isinstance(node, ast.Try) for node in ast.walk(function))
    return {
        "handler_found": True,
        "post_route_bound": route_bound,
        "request_json_parsed": request_json,
        "direct_state_subscript": direct_state,
        "local_try_present": local_try,
        "passed": route_bound and request_json and direct_state and not local_try,
    }


class TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def html_text(html: str) -> str:
    parser = TextExtractor()
    parser.feed(html)
    visible = " ".join(" ".join(parser.parts).split()).lower()
    return re.sub(r"\s+:", ":", visible)


def cwe_page_gate(html: str, *markers: str) -> bool:
    compact = html_text(html)
    return all(marker.lower() in compact for marker in markers)


def added_patch_lines(patch: str) -> list[str]:
    return [
        line[1:]
        for line in patch.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]


def froxlor_patch_gate(patch: str) -> dict:
    added = added_patch_lines(patch)
    joined = "\n".join(added)
    lower = joined.lower()
    validation = (
        "empty(trim($name))" in joined
        and "empty(trim($email))" in joined
        and "stringisempty" in joined
    )
    authorization_markers = sorted(
        marker
        for marker in ("authorization", "authorize", "permission", "access control")
        if marker in lower
    )
    return {
        "added_executable_lines": len(added),
        "nonempty_name_email_validation_added": validation,
        "authorization_markers_in_added_lines": authorization_markers,
        "authorization_semantics_established": bool(authorization_markers),
        "passed_as_insufficient_for_access_control": validation and not authorization_markers,
    }


def reference_relation(nvd: set[str], ghsa: set[str]) -> str:
    if nvd == ghsa:
        return "equal"
    if nvd < ghsa:
        return "nvd_subset_of_ghsa"
    if ghsa < nvd:
        return "ghsa_subset_of_nvd"
    if nvd & ghsa:
        return "overlap_non_subset"
    return "disjoint"


SUSE_REPAIR = re.compile(
    r"^(https://bugzilla\.suse\.com/show_bug\.cgi\?id=CVE-\d{4}-\d+)(?:https:/+)$"
)


def repair_suse_bug_lookup(url: str) -> str:
    match = SUSE_REPAIR.fullmatch(url)
    return match.group(1) if match else url


def label_for_reference_relation(relation: str) -> str:
    if relation in {"equal", "overlap_non_subset"}:
        return "representation_discrepancy"
    if relation in {"nvd_subset_of_ghsa", "ghsa_subset_of_nvd"}:
        return "incomplete"
    return "factual_conflict"


def analyze(manifest: dict) -> dict:
    required_flags = {
        "post_unsealing_targeted_diagnostic": True,
        "protocol_discovery_disclosed": True,
        "candidate_promotion_allowed": False,
        "eligible_for_human_gold_claim": False,
        "label_is_human": False,
    }
    for key, expected in required_flags.items():
        if manifest.get(key) is not expected:
            raise ValueError(f"sealed boundary drift for {key}")

    for name, record in manifest["inputs"].items():
        verified_path(record, f"sealed input:{name}")
    worklist_path = verified_path(manifest["output"]["worklist"], "sealed worklist")
    worklist = load_jsonl(worklist_path)
    if {row["sample_id"] for row in worklist} != EXPECTED_SAMPLE_IDS:
        raise ValueError("sealed residual sample set drift")
    rows = {row["cve_id"]: row for row in worklist}
    bodies = {
        name: evidence_body(record, name)
        for name, record in manifest["evidence"].items()
    }

    lightning_row = rows["CVE-2024-8020"]
    lightning_gate = lightning_source_gate(bodies["lightning_api_source"].decode("utf-8"))
    lightning_cwes = advisory_cwes(bodies["lightning_advisory"])
    cwe248_gate = cwe_page_gate(
        bodies["cwe_248"].decode("utf-8", errors="replace"),
        "CWE-248: Uncaught Exception",
        "exception is thrown",
        "not caught",
    )
    cwe400_gate = cwe_page_gate(
        bodies["cwe_400"].decode("utf-8", errors="replace"),
        "CWE-400: Uncontrolled Resource Consumption",
        "allocation and maintenance of a limited resource",
    )
    lightning_pass = (
        lightning_row["nvd_value"] == ["CWE-400"]
        and lightning_row["ghsa_value"] == ["CWE-248"]
        and "CWE-248" in lightning_cwes
        and lightning_gate["passed"]
        and cwe248_gate
        and cwe400_gate
    )

    froxlor_row = rows["CVE-2023-4304"]
    froxlor_gate = froxlor_patch_gate(bodies["froxlor_patch"].decode("utf-8"))
    froxlor_cwes = advisory_cwes(bodies["froxlor_advisory"])
    cwe840_gate = cwe_page_gate(
        bodies["cwe_840"].decode("utf-8", errors="replace"),
        "CWE CATEGORY: Business Logic Errors",
        "Vulnerability Mapping: PROHIBITED",
        "must not be used to map to real-world vulnerabilities",
    )
    froxlor_evidence_complete = (
        froxlor_row["nvd_value"] == ["CWE-840"]
        and set(froxlor_row["ghsa_value"]) == {"CWE-284", "CWE-862"}
        and {"CWE-284", "CWE-862"}.issubset(froxlor_cwes)
        and cwe840_gate
        and froxlor_gate["passed_as_insufficient_for_access_control"]
    )
    if not froxlor_evidence_complete:
        raise ValueError("frozen Froxlor/CWE evidence no longer satisfies the contract")

    k3s_row = rows["CVE-2023-32187"]
    malformed_texts = {
        name: " ".join(body.decode("utf-8", errors="replace").split())
        for name, body in bodies.items()
        if name.startswith("suse_malformed_")
    }
    malformed_gate = all(
        "Invalid Bug ID" in text and "is not a valid bug number nor an alias" in text
        for text in malformed_texts.values()
    )
    exact_nvd = set(k3s_row["nvd_value"])
    exact_ghsa = set(k3s_row["ghsa_value"])
    repaired_nvd = {repair_suse_bug_lookup(url) for url in exact_nvd}
    repaired_ghsa = {repair_suse_bug_lookup(url) for url in exact_ghsa}
    exact_relation = reference_relation(exact_nvd, exact_ghsa)
    repaired_relation = reference_relation(repaired_nvd, repaired_ghsa)
    exact_label = label_for_reference_relation(exact_relation)
    repaired_label = label_for_reference_relation(repaired_relation)
    k3s_advisory = json.loads(bodies["k3s_advisory"])
    k3s_evidence_complete = (
        k3s_advisory.get("ghsa_id") == "GHSA-m4hf-6vgr-75r2"
        and malformed_gate
        and exact_relation == "overlap_non_subset"
        and repaired_relation == "nvd_subset_of_ghsa"
        and exact_label != repaired_label
    )
    if not k3s_evidence_complete:
        raise ValueError("frozen K3s reference evidence no longer satisfies the contract")

    cases = [
        {
            "sample_id": lightning_row["sample_id"],
            "cve_id": lightning_row["cve_id"],
            "field": lightning_row["field"],
            "evidence_route": "source_local_exception_path",
            "gates": {
                "source": lightning_gate,
                "github_advisory_cwes": sorted(lightning_cwes),
                "official_cwe_248_definition": cwe248_gate,
                "official_cwe_400_definition": cwe400_gate,
                "all_passed": lightning_pass,
            },
            "development_typing_candidate": (
                "factual_conflict" if lightning_pass else "uncertain"
            ),
            "promoted_candidate": None,
            "candidate_promotion_allowed": False,
            "label_is_human": False,
        },
        {
            "sample_id": froxlor_row["sample_id"],
            "cve_id": froxlor_row["cve_id"],
            "field": froxlor_row["field"],
            "evidence_route": "mapping_validity_and_patch_semantics",
            "gates": {
                "official_cwe_840_mapping_prohibited": cwe840_gate,
                "github_advisory_cwes": sorted(froxlor_cwes),
                "patch": froxlor_gate,
                "evidence_complete": froxlor_evidence_complete,
                "construct_relation_resolved": False,
            },
            "development_typing_candidate": "uncertain",
            "promoted_candidate": None,
            "candidate_promotion_allowed": False,
            "label_is_human": False,
        },
        {
            "sample_id": k3s_row["sample_id"],
            "cve_id": k3s_row["cve_id"],
            "field": k3s_row["field"],
            "evidence_route": "reference_identity_profile_sensitivity",
            "gates": {
                "malformed_resources_verified": malformed_gate,
                "profiles": {
                    "frozen_http_resource": {
                        "relation": exact_relation,
                        "candidate": exact_label,
                    },
                    "intended_bug_lookup_repair": {
                        "relation": repaired_relation,
                        "candidate": repaired_label,
                    },
                },
                "evidence_complete": k3s_evidence_complete,
                "construct_relation_resolved": False,
            },
            "development_typing_candidate": "uncertain",
            "promoted_candidate": None,
            "candidate_promotion_allowed": False,
            "label_is_human": False,
        },
    ]
    counts = Counter(case["development_typing_candidate"] for case in cases)
    if counts != Counter({"uncertain": 2, "factual_conflict": 1}):
        raise ValueError(f"fixed residual outcome drift: {counts}")
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "rq2_residual_nonaffected_evidence_analysis",
        "cases": cases,
        "summary": {
            "row_count": 3,
            "development_candidate_counts": dict(sorted(counts.items())),
            "promoted_candidate_count": 0,
            "mechanism_supported_rows": 1,
            "construct_unresolved_rows": 2,
            "original_rq2_combined_candidate_unchanged": "1219/1250",
            "status": "targeted_residual_diagnostic_no_promotion",
        },
        "advancement_gate": {
            "post_unsealing_targeted_diagnostic": True,
            "protocol_discovery_disclosed": True,
            "candidate_promotion_allowed": False,
            "eligible_for_human_gold_claim": False,
            "label_is_human": False,
        },
    }


def summary_markdown(analysis: dict) -> str:
    by_id = {case["cve_id"]: case for case in analysis["cases"]}
    k3s = by_id["CVE-2023-32187"]["gates"]["profiles"]
    return "\n".join(
        [
            "# RQ2 Residual Non-Affected Evidence v1",
            "",
            "> Post-unsealing targeted diagnostic; not human gold.",
            "",
            "- Rows: `3`",
            "- Mechanism-supported development candidates: `1/3`",
            "- Construct-unresolved: `2/3`",
            "- Promoted candidates: `0`",
            "- Combined RQ2 candidate: unchanged at `1219/1250` (`0.9752`)",
            "- Status: `targeted_residual_diagnostic_no_promotion`",
            "",
            "| CVE | Field | Evidence result | Development candidate |",
            "|---|---|---|---|",
            "| CVE-2024-8020 | cwe_ids | direct unhandled `body[\"state\"]` path supports CWE-248 | factual_conflict |",
            "| CVE-2023-4304 | cwe_ids | CWE-840 mapping prohibited; patch does not establish authorization semantics | uncertain |",
            (
                "| CVE-2023-32187 | references | frozen HTTP = "
                f"{k3s['frozen_http_resource']['candidate']}; intended repair = "
                f"{k3s['intended_bug_lookup_repair']['candidate']} | uncertain |"
            ),
            "",
            "All outputs retain `label_is_human=false` and `candidate_promotion_allowed=false`.",
            "",
        ]
    )


def main() -> int:
    args = parse_args()
    seal_path = resolve(args.seal)
    output_dir = resolve(args.output_dir)
    manifest = json.loads(seal_path.read_text(encoding="utf-8"))
    analysis = analyze(manifest)
    output_dir.mkdir(parents=True, exist_ok=True)
    analysis_path = output_dir / "analysis.json"
    summary_path = output_dir / "summary.md"
    result_manifest_path = output_dir / "manifest.json"
    analysis_path.write_text(canonical_json(analysis), encoding="utf-8")
    summary_path.write_text(summary_markdown(analysis), encoding="utf-8")
    result_manifest = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "rq2_residual_nonaffected_evidence_result_manifest",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "seal": {"path": portable_path(seal_path), "sha256": sha256(seal_path)},
            "analyzer": {
                "path": portable_path(Path(__file__).resolve()),
                "sha256": sha256(Path(__file__).resolve()),
            },
        },
        "outputs": {
            "analysis": {
                "path": portable_path(analysis_path),
                "sha256": sha256(analysis_path),
            },
            "summary": {
                "path": portable_path(summary_path),
                "sha256": sha256(summary_path),
            },
        },
        "candidate_promotion_allowed": False,
        "eligible_for_human_gold_claim": False,
        "label_is_human": False,
    }
    result_manifest_path.write_text(canonical_json(result_manifest), encoding="utf-8")
    print(json.dumps(analysis["summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
