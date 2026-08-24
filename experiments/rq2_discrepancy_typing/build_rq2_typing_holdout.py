#!/usr/bin/env python3
"""Freeze a development-CVE-disjoint, prediction-sealed RQ2 typing holdout."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from analyze_cwe_taxonomy_variants import (  # noqa: E402
    CweCatalog,
    relation_profile,
    taxonomy_v1_status,
)
from build_field_discrepancies import compare_references  # noqa: E402


DEFAULT_FIELD_VIEWS = (
    "data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl"
)
DEFAULT_ALIGNED = "data/processed/bootstrap/aligned/nvd_ghsa_by_cve.jsonl"
DEFAULT_PRIMARY = "data/annotations/rq2/discrepancy_typing_seed.jsonl"
DEFAULT_REFERENCE_IMPACT = (
    "results/rq2_discrepancy_typing/reference_normalization_impact_validation/"
    "reference_identity_secondary_worklist.masked.jsonl"
)
DEFAULT_REFERENCE_COMBINED = (
    "results/rq2_discrepancy_typing/reference_normalization_impact_validation/"
    "reference_normalization_combined_candidate.jsonl"
)
DEFAULT_CWE_IMPACT = (
    "results/rq2_discrepancy_typing/cwe_taxonomy/impact_holdout/"
    "cwe_taxonomy_impact_worklist.blind.jsonl"
)
DEFAULT_PHASE_D_AFFECTED = (
    "data/annotations/phase_d/affected_versions_fc_manual_check.jsonl"
)
DEFAULT_PHASE_D_SEVERITY = (
    "data/annotations/phase_d/severity_fc_adjudication_seed.jsonl"
)
DEFAULT_AFFECTED_V1 = "data/annotations/holdout/affected_versions_v1/source_rows.jsonl"
DEFAULT_AFFECTED_V2 = "data/annotations/holdout/affected_versions_v2/source_rows.jsonl"
DEFAULT_CWE_CHANGES = (
    "results/rq2_discrepancy_typing/cwe_taxonomy/"
    "cwe_taxonomy_changed_cases.jsonl"
)
DEFAULT_CWE_ZIP = "data/external/cwe/cwec_v4.20.xml.zip"
DEFAULT_PROMPT = "docs/prompts/rq2_typing_holdout_review.md"
DEFAULT_OUTPUT_DIR = "data/annotations/holdout/rq2_typing_v1"
DEFAULT_SEED = "rq2_typing_holdout_v1_20260715"
FIELDS = (
    "severity",
    "published",
    "references",
    "affected_versions",
    "cwe_ids",
)
LABELS = (
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
)
FORBIDDEN_BLIND_KEY_PARTS = (
    "annotation",
    "baseline",
    "candidate",
    "correct",
    "gold",
    "method",
    "prediction",
    "selection",
    "silver",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--field-views", default=DEFAULT_FIELD_VIEWS)
    parser.add_argument("--aligned", default=DEFAULT_ALIGNED)
    parser.add_argument("--primary-exclusion", default=DEFAULT_PRIMARY)
    parser.add_argument("--reference-impact", default=DEFAULT_REFERENCE_IMPACT)
    parser.add_argument("--reference-combined", default=DEFAULT_REFERENCE_COMBINED)
    parser.add_argument("--cwe-impact", default=DEFAULT_CWE_IMPACT)
    parser.add_argument("--phase-d-affected-exclusion", default=DEFAULT_PHASE_D_AFFECTED)
    parser.add_argument("--phase-d-severity-exclusion", default=DEFAULT_PHASE_D_SEVERITY)
    parser.add_argument("--affected-v1-exclusion", default=DEFAULT_AFFECTED_V1)
    parser.add_argument("--affected-v2-exclusion", default=DEFAULT_AFFECTED_V2)
    parser.add_argument("--cwe-changes", default=DEFAULT_CWE_CHANGES)
    parser.add_argument("--cwe-xml-zip", default=DEFAULT_CWE_ZIP)
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--seed", default=DEFAULT_SEED)
    parser.add_argument("--rows-per-field", type=int, default=250)
    parser.add_argument(
        "--review-backend",
        choices=["openai", "codex-cli"],
        default="openai",
    )
    parser.add_argument("--review-model", default="gpt-5.5")
    parser.add_argument("--review-max-output-tokens", type=int, default=512)
    parser.add_argument("--codex-cli-path", default="codex")
    parser.add_argument(
        "--codex-reasoning-effort",
        choices=["low", "medium", "high", "xhigh"],
        default="high",
    )
    parser.add_argument("--expected-field-view-rows", type=int, default=8066)
    parser.add_argument("--expected-exclusion-cves", type=int, default=717)
    parser.add_argument("--force", action="store_true")
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


def codex_cli_contract(path_value: str, model: str, reasoning_effort: str) -> dict:
    executable = shutil.which(path_value)
    if not executable:
        raise FileNotFoundError(f"Codex CLI executable not found: {path_value}")
    path = Path(executable).resolve()
    result = subprocess.run(
        [str(path), "--version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    version = result.stdout.strip()
    if not version.startswith("codex-cli "):
        raise ValueError(f"unexpected Codex CLI version output: {version}")
    return {
        "backend": "codex-cli",
        "api_route": "codex_cli",
        "path": str(path),
        "version": version,
        "sha256": sha256(path),
        "model": model,
        "reasoning_effort": reasoning_effort,
        "max_output_tokens": None,
        "sandbox": "read-only",
        "ephemeral": True,
    }


def openai_contract(model: str, max_output_tokens: int) -> dict:
    import openai

    return {
        "backend": "openai",
        "api_route": "primary",
        "version": f"openai-python {openai.__version__}",
        "sha256": None,
        "model": model,
        "reasoning_effort": None,
        "max_output_tokens": max_output_tokens,
        "temperature": 0,
        "response_format": "strict_json_schema",
    }


def iter_jsonl(path: Path, include_line: bool = False):
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{line_number}") from exc
            if include_line:
                row = {**row, "_source_line_number": line_number}
            yield row


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    os.replace(temporary, path)


def write_jsonl(path: Path, rows: list[dict]) -> None:
    lines = []
    for row in rows:
        lines.append(json.dumps(row, ensure_ascii=False, sort_keys=True))
    atomic_write_text(path, "\n".join(lines) + "\n")


def rank_key(seed: str, field: str, status: str, cve_id: str) -> tuple[str, str]:
    digest = hashlib.sha256(
        f"{seed}:{field}:{status}:{cve_id}".encode("utf-8")
    ).hexdigest()
    return digest, cve_id


def equal_waterfill_quotas(counts: dict[str, int], target: int) -> dict[str, int]:
    if target < 1:
        raise ValueError("target must be positive")
    if sum(counts.values()) < target:
        raise ValueError(f"target={target} exceeds candidates={sum(counts.values())}")
    quotas = {status: 0 for status, count in counts.items() if count > 0}
    status_order = {status: index for index, status in enumerate(LABELS)}
    for _ in range(target):
        eligible = [
            status for status in quotas if quotas[status] < counts[status]
        ]
        if not eligible:
            raise AssertionError("waterfill exhausted before reaching target")
        chosen = min(
            eligible,
            key=lambda status: (quotas[status], status_order.get(status, 999), status),
        )
        quotas[chosen] += 1
    return quotas


def hybrid_stratum_quotas(
    counts: dict[str, int],
    target: int,
    proportional_fraction: float = 0.70,
) -> dict[str, int]:
    """Allocate a proportional core and an equal-coverage audit supplement."""
    nonempty = {status: count for status, count in counts.items() if count > 0}
    if not 0 <= proportional_fraction <= 1:
        raise ValueError("proportional_fraction must be between 0 and 1")
    if sum(nonempty.values()) < target:
        raise ValueError(f"target={target} exceeds candidates={sum(nonempty.values())}")
    proportional_target = round(target * proportional_fraction)
    total = sum(nonempty.values())
    exact = {
        status: proportional_target * count / total
        for status, count in nonempty.items()
    }
    quotas = {
        status: min(count, int(exact[status]))
        for status, count in nonempty.items()
    }
    remainder_order = sorted(
        nonempty,
        key=lambda status: (
            -(exact[status] - int(exact[status])),
            LABELS.index(status) if status in LABELS else 999,
            status,
        ),
    )
    while sum(quotas.values()) < proportional_target:
        progressed = False
        for status in remainder_order:
            if quotas[status] >= nonempty[status]:
                continue
            quotas[status] += 1
            progressed = True
            if sum(quotas.values()) == proportional_target:
                break
        if not progressed:
            break

    equal_added = {status: 0 for status in nonempty}
    status_order = {status: index for index, status in enumerate(LABELS)}
    while sum(quotas.values()) < target:
        eligible = [
            status for status in nonempty if quotas[status] < nonempty[status]
        ]
        if not eligible:
            raise AssertionError("hybrid allocation exhausted before reaching target")
        chosen = min(
            eligible,
            key=lambda status: (
                equal_added[status],
                status_order.get(status, 999),
                status,
            ),
        )
        quotas[chosen] += 1
        equal_added[chosen] += 1
    return quotas


def select_globally_unique_strata(
    ranked_strata: dict[tuple[str, str], list[dict]],
    quotas: dict[tuple[str, str], int],
) -> list[tuple[dict, str, str]]:
    """Fill every field/status quota through deterministic bipartite matching."""
    field_order = {field: index for index, field in enumerate(FIELDS)}
    status_order = {status: index for index, status in enumerate(LABELS)}
    keys = sorted(
        quotas,
        key=lambda key: (
            field_order.get(key[0], 999),
            status_order.get(key[1], 999),
            key,
        ),
    )
    slots = [
        (key, index)
        for key in keys
        for index in range(quotas[key])
    ]
    slots.sort(
        key=lambda slot: (
            len(ranked_strata[slot[0]]) / quotas[slot[0]],
            field_order.get(slot[0][0], 999),
            status_order.get(slot[0][1], 999),
            slot[1],
        )
    )
    if sys.getrecursionlimit() < len(slots) * 2:
        sys.setrecursionlimit(len(slots) * 2)
    slot_to_row: dict[tuple[tuple[str, str], int], dict] = {}
    cve_to_slot: dict[str, tuple[tuple[str, str], int]] = {}

    def augment(
        slot: tuple[tuple[str, str], int],
        seen_cves: set[str],
    ) -> bool:
        for row in ranked_strata[slot[0]]:
            cve_id = row["cve_id"]
            if cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)
            occupied = cve_to_slot.get(cve_id)
            if occupied is not None and not augment(occupied, seen_cves):
                continue
            cve_to_slot[cve_id] = slot
            slot_to_row[slot] = row
            return True
        return False

    for slot in slots:
        if not augment(slot, set()):
            field, status = slot[0]
            raise ValueError(
                "global CVE uniqueness makes the requested strata infeasible at "
                f"{field}:{status} slot {slot[1] + 1}/{quotas[slot[0]]}"
            )

    selected = [
        (slot_to_row[(key, index)], key[0], key[1])
        for key in keys
        for index in range(quotas[key])
    ]
    if len(cve_to_slot) != len(selected):
        raise AssertionError("global unique selector emitted a duplicate CVE")
    return selected


def forbidden_blind_keys(value: object, prefix: str = "") -> list[str]:
    found = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if any(part in str(key).lower() for part in FORBIDDEN_BLIND_KEY_PARTS):
                found.append(path)
            found.extend(forbidden_blind_keys(child, path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(forbidden_blind_keys(child, f"{prefix}[{index}]"))
    return found


def unique_by_cve(rows, name: str) -> dict[str, dict]:
    result = {}
    for row in rows:
        cve_id = row.get("cve_id")
        if not cve_id or cve_id in result:
            raise ValueError(f"{name} has missing or duplicate cve_id={cve_id}")
        result[cve_id] = row
    return result


def cve_set(path: Path) -> set[str]:
    values = {str(row.get("cve_id") or "") for row in iter_jsonl(path)}
    if "" in values:
        raise ValueError(f"{path} contains a row without cve_id")
    return values


def aligned_context(row: dict) -> dict:
    nvd = row.get("nvd") or {}
    ghsa_rows = row.get("ghsa") or []
    ghsa = ghsa_rows[0] if ghsa_rows else {}
    return {
        "nvd_summary": nvd.get("summary"),
        "ghsa_summary": ghsa.get("summary"),
    }


def taxonomy_entries(values: list[str], catalog: CweCatalog) -> list[dict]:
    identifiers = sorted(
        {
            str(value).upper().removeprefix("CWE-")
            for value in values
        },
        key=lambda value: (not value.isdigit(), int(value) if value.isdigit() else value),
    )
    return [
        catalog.entries.get(
            identifier,
            {
                "cwe_id": f"CWE-{identifier}",
                "name": None,
                "abstraction": None,
                "status": "not_in_research_concepts_catalog",
                "description": "",
            },
        )
        for identifier in identifiers
    ]


def raw_reference_urls(record: dict) -> list[str]:
    return sorted(
        {
            str(item.get("url"))
            for item in record.get("references") or []
            if item.get("url")
        }
    )


def raw_package_names(record: dict) -> list[str]:
    return sorted(
        {
            str(item.get("package_name") or item.get("product"))
            for item in record.get("affected") or []
            if item.get("package_name") or item.get("product")
        }
    )


def raw_field_values(aligned: dict, field: str) -> tuple[object, object]:
    nvd = aligned.get("nvd") or {}
    ghsa_rows = aligned.get("ghsa") or []
    if len(ghsa_rows) != 1:
        raise ValueError(f"{aligned.get('cve_id')}: expected one GHSA row")
    ghsa = ghsa_rows[0]
    if field == "severity":
        return nvd.get("severity"), ghsa.get("severity")
    if field == "published":
        return nvd.get("published"), ghsa.get("published")
    if field == "references":
        return raw_reference_urls(nvd), raw_reference_urls(ghsa)
    if field == "affected_versions":
        return nvd.get("affected") or [], ghsa.get("affected") or []
    if field == "cwe_ids":
        return nvd.get("cwe_ids") or [], ghsa.get("cwe_ids") or []
    raise ValueError(f"unsupported field={field}")


def source_row(
    row: dict,
    field: str,
    sample_id: str,
    stratum_count: int,
    stratum_sampled: int,
    aligned: dict,
    catalog: CweCatalog,
) -> dict:
    discrepancy = row["field_discrepancies"][field]
    nvd_raw, ghsa_raw = raw_field_values(aligned, field)
    nvd_record = aligned.get("nvd") or {}
    ghsa_record = (aligned.get("ghsa") or [])[0]
    field_context = {
        "vulnerability_context": aligned_context(aligned),
    }
    if field == "cwe_ids":
        field_context["official_cwe_entries"] = taxonomy_entries(
            [*list(nvd_raw or []), *list(ghsa_raw or [])], catalog
        )
        field_context["taxonomy_source"] = {
            "catalog_version": catalog.version,
            "catalog_date": catalog.date,
            "view_id": "1000",
        }
    return {
        "sample_id": sample_id,
        "source_line_number": row["_source_line_number"],
        "cve_id": row["cve_id"],
        "nvd_source_id": row.get("nvd_source_id"),
        "ghsa_source_id": row.get("ghsa_source_id"),
        "field": field,
        "baseline_status": discrepancy["status"],
        "baseline_note": discrepancy.get("note"),
        "nvd_value": nvd_raw,
        "ghsa_value": ghsa_raw,
        "field_context": field_context,
        "package_names": {
            "nvd": raw_package_names(nvd_record),
            "ghsa": raw_package_names(ghsa_record),
        },
        "reference_context": {
            "nvd_urls": raw_reference_urls(nvd_record),
            "ghsa_urls": raw_reference_urls(ghsa_record),
        },
        "sampling_stratum": {
            "field": field,
            "baseline_status": discrepancy["status"],
            "eligible_rows": stratum_count,
            "sampled_rows": stratum_sampled,
            "design_weight": stratum_count / stratum_sampled,
        },
    }


def blind_row(row: dict) -> dict:
    result = {
        key: row[key]
        for key in (
            "sample_id",
            "cve_id",
            "nvd_source_id",
            "ghsa_source_id",
            "field",
            "nvd_value",
            "ghsa_value",
            "field_context",
            "package_names",
            "reference_context",
        )
    }
    result["review_contract"] = {
        "labels": [*LABELS, "uncertain"],
        "confidence": ["high", "medium", "low"],
        "typing_only": True,
    }
    forbidden = forbidden_blind_keys(result)
    if forbidden:
        raise ValueError(f"blind row contains forbidden keys: {forbidden[:5]}")
    return result


def prediction_row(
    row: dict,
    original_reference_changes: dict[str, str],
    audited_reference_changes: dict[str, str],
    cwe_changes: dict[str, str],
) -> dict:
    current = row["baseline_status"]
    original_reference = (
        original_reference_changes.get(row["cve_id"], current)
        if row["field"] == "references"
        else current
    )
    audited_reference = (
        audited_reference_changes.get(row["cve_id"], current)
        if row["field"] == "references"
        else current
    )
    cwe = (
        cwe_changes.get(row["cve_id"], current)
        if row["field"] == "cwe_ids"
        else current
    )
    combined_original = original_reference if row["field"] == "references" else cwe
    combined_audited = audited_reference if row["field"] == "references" else cwe
    return {
        "sample_id": row["sample_id"],
        "cve_id": row["cve_id"],
        "field": row["field"],
        "current": current,
        "reference_resource_identity_original_v1": original_reference,
        "reference_resource_identity_audited_v1": audited_reference,
        "cwe_taxonomy_v1": cwe,
        "combined_original_v1": combined_original,
        "combined_audited_v1": combined_audited,
    }


def main() -> int:
    args = parse_args()
    if args.review_max_output_tokens < 1:
        raise ValueError("--review-max-output-tokens must be positive")
    review_execution = (
        codex_cli_contract(
            args.codex_cli_path,
            args.review_model,
            args.codex_reasoning_effort,
        )
        if args.review_backend == "codex-cli"
        else openai_contract(args.review_model, args.review_max_output_tokens)
    )
    paths = {
        "field_views": resolve(args.field_views),
        "aligned": resolve(args.aligned),
        "primary_exclusion": resolve(args.primary_exclusion),
        "reference_impact": resolve(args.reference_impact),
        "reference_combined": resolve(args.reference_combined),
        "cwe_impact": resolve(args.cwe_impact),
        "phase_d_affected_exclusion": resolve(args.phase_d_affected_exclusion),
        "phase_d_severity_exclusion": resolve(args.phase_d_severity_exclusion),
        "affected_v1_exclusion": resolve(args.affected_v1_exclusion),
        "affected_v2_exclusion": resolve(args.affected_v2_exclusion),
        "cwe_changes": resolve(args.cwe_changes),
        "cwe_xml_zip": resolve(args.cwe_xml_zip),
        "prompt": resolve(args.prompt),
        "field_predictor": resolve("scripts/build_field_discrepancies.py"),
        "runner": resolve("scripts/run_expert_candidate_annotation.py"),
        "merge": resolve(
            "experiments/rq2_discrepancy_typing/merge_rq2_typing_holdout_reviews.py"
        ),
        "evaluator": resolve(
            "experiments/rq2_discrepancy_typing/evaluate_rq2_typing_holdout.py"
        ),
    }
    for path in paths.values():
        if not path.exists():
            raise FileNotFoundError(path)
    input_hashes = {name: sha256(path) for name, path in paths.items()}

    output_dir = resolve(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    lock_path = output_dir / ".build.lock"
    lock_handle = lock_path.open("a+", encoding="utf-8")
    try:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise RuntimeError(f"another holdout build holds {lock_path}") from exc
    blind_dir = output_dir / "blind"
    source_path = output_dir / "source_rows.jsonl"
    prediction_path = output_dir / "predictions.sealed.jsonl"
    blind_a_path = blind_dir / "worklist_a.blind.jsonl"
    blind_b_path = blind_dir / "worklist_b.blind.jsonl"
    manifest_path = output_dir / "manifest.sealed.json"
    reviewer_a = output_dir / "reviewer_a.jsonl"
    reviewer_b = output_dir / "reviewer_b.jsonl"
    if reviewer_a.exists() or reviewer_b.exists():
        raise FileExistsError("reviewer output exists; sealed holdout cannot be rebuilt")
    outputs = [
        source_path,
        prediction_path,
        blind_a_path,
        blind_b_path,
        manifest_path,
    ]
    if not args.force and any(path.exists() for path in outputs):
        raise FileExistsError("holdout outputs already exist; use --force before review")

    field_rows = list(iter_jsonl(paths["field_views"], include_line=True))
    if len(field_rows) != args.expected_field_view_rows:
        raise ValueError(
            f"expected {args.expected_field_view_rows} field-view rows, found {len(field_rows)}"
        )
    field_by_cve = unique_by_cve(field_rows, "field views")
    aligned_all = unique_by_cve(iter_jsonl(paths["aligned"]), "aligned rows")
    missing_aligned = set(field_by_cve) - set(aligned_all)
    if missing_aligned:
        raise ValueError(
            f"field-view CVEs missing from aligned rows: {sorted(missing_aligned)[:5]}"
        )
    aligned = {cve_id: aligned_all[cve_id] for cve_id in field_by_cve}

    exclusion_paths = {
        "primary": paths["primary_exclusion"],
        "reference_impact": paths["reference_impact"],
        "cwe_impact": paths["cwe_impact"],
        "phase_d_affected": paths["phase_d_affected_exclusion"],
        "phase_d_severity": paths["phase_d_severity_exclusion"],
        "affected_versions_v1": paths["affected_v1_exclusion"],
        "affected_versions_v2": paths["affected_v2_exclusion"],
    }
    exclusion_sets = {
        name: cve_set(path) for name, path in exclusion_paths.items()
    }
    excluded = set().union(*exclusion_sets.values())
    if len(excluded) != args.expected_exclusion_cves:
        raise ValueError(
            f"expected {args.expected_exclusion_cves} excluded CVEs, found {len(excluded)}"
        )
    missing_exclusions = excluded - set(field_by_cve)
    if missing_exclusions:
        raise ValueError(f"exclusion CVEs missing from field views: {sorted(missing_exclusions)[:5]}")

    catalog = CweCatalog(paths["cwe_xml_zip"])
    ranked_strata: dict[tuple[str, str], list[dict]] = {}
    stratum_quotas: dict[tuple[str, str], int] = {}
    stratum_counts: dict[tuple[str, str], int] = {}
    stratum_manifest = []
    for field in FIELDS:
        strata: dict[str, list[dict]] = defaultdict(list)
        for row in field_rows:
            if row["cve_id"] in excluded:
                continue
            discrepancy = row["field_discrepancies"].get(field)
            if not discrepancy or discrepancy.get("status") not in LABELS:
                raise ValueError(f"{row['cve_id']}: invalid {field} discrepancy")
            strata[discrepancy["status"]].append(row)
        counts = {status: len(rows) for status, rows in strata.items()}
        quotas = hybrid_stratum_quotas(counts, args.rows_per_field)
        if sum(quotas.values()) != args.rows_per_field:
            raise AssertionError("stratum quotas do not sum to rows_per_field")
        for status in LABELS:
            if status not in quotas:
                continue
            ranked = sorted(
                strata[status],
                key=lambda row: rank_key(args.seed, field, status, row["cve_id"]),
            )
            key = (field, status)
            ranked_strata[key] = ranked
            stratum_quotas[key] = quotas[status]
            stratum_counts[key] = counts[status]
            stratum_manifest.append(
                {
                    "field": field,
                    "baseline_status": status,
                    "eligible_rows": counts[status],
                    "sampled_rows": quotas[status],
                    "design_weight": counts[status] / quotas[status],
                }
            )

    selected_specs = [
        (
            row,
            field,
            status,
            stratum_counts[(field, status)],
            stratum_quotas[(field, status)],
        )
        for row, field, status in select_globally_unique_strata(
            ranked_strata, stratum_quotas
        )
    ]
    selected_specs.sort(
        key=lambda item: rank_key(args.seed + ":global", item[1], item[2], item[0]["cve_id"])
    )
    expected_rows = args.rows_per_field * len(FIELDS)
    if len(selected_specs) != expected_rows:
        raise ValueError(f"expected {expected_rows} selected rows, found {len(selected_specs)}")
    if len({item[0]["cve_id"] for item in selected_specs}) != expected_rows:
        raise ValueError("selected holdout CVEs are not globally unique across fields")
    source_rows = []
    for index, (row, field, _status, count, sampled) in enumerate(selected_specs, 1):
        source_rows.append(
            source_row(
                row,
                field,
                f"rq2_typing_holdout_v1:{index:03d}",
                count,
                sampled,
                aligned[row["cve_id"]],
                catalog,
            )
        )
    if {row["cve_id"] for row in source_rows} & excluded:
        raise AssertionError("selected holdout overlaps an excluded CVE")

    reference_rows = list(iter_jsonl(paths["reference_combined"]))
    expected_reference_changes = {
        row["cve_id"]: "incomplete"
        for row in reference_rows
        if row.get("candidate_incomplete_supported") is True
    }
    if len(reference_rows) != 56 or len(expected_reference_changes) != 32:
        raise ValueError("expected 56 reference impact rows and 32 strict-supported changes")
    cwe_rows = list(iter_jsonl(paths["cwe_changes"]))
    expected_cwe_changes = {
        row["cve_id"]: row["taxonomy_v1_status"] for row in cwe_rows
    }
    if len(cwe_rows) != 17 or len(expected_cwe_changes) != 17:
        raise ValueError("expected 17 unique CWE taxonomy changes")

    original_reference_changes = {}
    audited_reference_changes = {}
    cwe_changes = {}
    for cve_id, row in field_by_cve.items():
        aligned_row = aligned[cve_id]
        nvd = aligned_row.get("nvd") or {}
        ghsa_rows = aligned_row.get("ghsa") or []
        if len(ghsa_rows) != 1:
            raise ValueError(f"{cve_id}: expected exactly one aligned GHSA record")
        original_reference = compare_references(
            nvd,
            ghsa_rows[0],
            normalization_profile="resource_identity_v1",
        )["status"]
        audited_reference = compare_references(
            nvd,
            ghsa_rows[0],
            normalization_profile="resource_identity_audited_v1",
        )["status"]
        current_reference = row["field_discrepancies"]["references"]["status"]
        if original_reference != current_reference:
            original_reference_changes[cve_id] = original_reference
        if audited_reference != current_reference:
            audited_reference_changes[cve_id] = audited_reference

        cwe_discrepancy = row["field_discrepancies"]["cwe_ids"]
        cwe_profile = relation_profile(
            list(cwe_discrepancy.get("nvd_value") or []),
            list(cwe_discrepancy.get("ghsa_value") or []),
            catalog,
        )
        audited_cwe = taxonomy_v1_status(cwe_discrepancy["status"], cwe_profile)
        if audited_cwe != cwe_discrepancy["status"]:
            cwe_changes[cve_id] = audited_cwe
    expected_original_reference_changes = {
        row["cve_id"]: "incomplete" for row in reference_rows
    }
    if original_reference_changes != expected_original_reference_changes:
        raise ValueError("callable original reference predictor does not reproduce 56-row impact")
    if audited_reference_changes != expected_reference_changes:
        raise ValueError("callable audited reference predictor does not reproduce 32-row audit")
    if cwe_changes != expected_cwe_changes:
        raise ValueError("callable CWE taxonomy predictor does not reproduce 17-row audit")
    predictions = [
        prediction_row(
            row,
            original_reference_changes,
            audited_reference_changes,
            cwe_changes,
        )
        for row in source_rows
    ]
    changed_predictions = [
        row
        for row in predictions
        if len(
            {
                row["current"],
                row["reference_resource_identity_original_v1"],
                row["reference_resource_identity_audited_v1"],
                row["cwe_taxonomy_v1"],
                row["combined_original_v1"],
                row["combined_audited_v1"],
            }
        )
        > 1
    ]
    if changed_predictions:
        raise ValueError("development-impact exclusion failed; candidate predictions differ")

    blind_a = [blind_row(row) for row in source_rows]
    blind_b = list(reversed(blind_a))
    if [row["sample_id"] for row in blind_a] != list(
        reversed([row["sample_id"] for row in blind_b])
    ):
        raise AssertionError("reviewer B worklist is not the exact reverse of reviewer A")

    blind_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(source_path, source_rows)
    write_jsonl(prediction_path, predictions)
    write_jsonl(blind_a_path, blind_a)
    write_jsonl(blind_b_path, blind_b)
    for name, path in paths.items():
        if sha256(path) != input_hashes[name]:
            raise ValueError(f"input changed during holdout build: {name}")

    output_map = {
        "source_rows": source_path,
        "predictions": prediction_path,
        "blind_worklist_a": blind_a_path,
        "blind_worklist_b": blind_b_path,
    }
    manifest = {
        "artifact_type": "rq2_typing_holdout_v1_manifest",
        "sealed_at_ns": time.time_ns(),
        "contains_annotations": False,
        "contains_human_labels": False,
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "selection_uses_gold": False,
        "selection_uses_reviewer_outputs": False,
        "selection_uses_current_status_for_balanced_stratification": True,
        "seed": args.seed,
        "sampling_algorithm": (
            "70% proportional plus 30% equal audit allocation across nonempty "
            "current-status strata per field; ascending "
            "sha256(seed:field:status:cve_id) within stratum; deterministic "
            "bipartite quota matching with global CVE uniqueness"
        ),
        "rows_per_field": args.rows_per_field,
        "selected_rows": len(source_rows),
        "selected_unique_cves": len({row["cve_id"] for row in source_rows}),
        "field_counts": dict(sorted(Counter(row["field"] for row in source_rows).items())),
        "strata": stratum_manifest,
        "exclusions": {
            name: {"path": str(exclusion_paths[name]), "cves": len(values)}
            for name, values in exclusion_sets.items()
        },
        "excluded_union_cves": len(excluded),
        "candidate_profile_comparison_identifiable": False,
        "candidate_profile_prediction_differences": 0,
        "prediction_profiles": [
            "current",
            "reference_resource_identity_original_v1",
            "reference_resource_identity_audited_v1",
            "cwe_taxonomy_v1",
            "combined_original_v1",
            "combined_audited_v1",
        ],
        "blind_projection": (
            "Raw aligned NVD/GHSA field values plus source summaries, package names, "
            "reference URLs, and individual official CWE entries; no normalized values, "
            "taxonomy paths, baseline labels, predictions, or selection strata."
        ),
        "candidate_profile_boundary": (
            "All known reference/CWE development-impact CVEs are excluded. The holdout "
            "tests fresh-CVE typing stability; it cannot estimate the audited profiles' "
            "impact, which remains confined to separate complete-impact audits."
        ),
        "inputs": {
            name: {"path": str(path), "sha256": input_hashes[name]}
            for name, path in paths.items()
        },
        "outputs": {
            name: {"path": str(path), "sha256": sha256(path)}
            for name, path in output_map.items()
        },
        "review_protocol": {
            "runner_contract_mode": "strict",
            "execution_backend": args.review_backend,
            "execution_contract": review_execution,
            "reviewer_a_pass_id": "rq2_typing_holdout_v1_reviewer_a",
            "reviewer_b_pass_id": "rq2_typing_holdout_v1_reviewer_b",
            "reviewer_a_output": str(reviewer_a),
            "reviewer_b_output": str(reviewer_b),
            "strict_consensus": (
                "exact non-uncertain label agreement, neither confidence low, and neither "
                "reviewer requests human review"
            ),
        },
        "source_inputs_unchanged_during_build": True,
    }
    atomic_write_text(
        manifest_path,
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
    )
    print(f"Wrote {source_path}")
    print(f"Wrote {prediction_path}")
    print(f"Wrote {blind_a_path}")
    print(f"Wrote {blind_b_path}")
    print(f"Wrote {manifest_path}")
    print(f"Selected rows={len(source_rows)}, unique CVEs={manifest['selected_unique_cves']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
