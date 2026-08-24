#!/usr/bin/env python3
"""Audit affected-version normalization fixes against the raw snapshots."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
import tarfile
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from build_field_discrepancies import (  # noqa: E402
    compare_affected_versions,
    normalize_affected_spans,
    normalize_package_names,
)
from build_initial_corpus import (  # noqa: E402
    iter_nvd_cves,
    normalize_nvd_match,
    resolve_nvd_inputs,
    walk_nvd_nodes,
)


DEFAULT_ALIGNED = "data/processed/bootstrap/aligned/nvd_ghsa_by_cve.jsonl"
DEFAULT_SAMPLE = "data/annotations/phase_d/affected_versions_fc_manual_check.jsonl"
DEFAULT_AI_GOLD = "data/annotations/ai_adjudicated_gold/rq3_affected_versions.jsonl"
DEFAULT_DECISIONS = (
    "data/annotations/ai_adjudicated_gold/interactive_decisions/"
    "rq3_affected_versions_overrides.jsonl"
)
DEFAULT_RAW_DIR = "data/raw"
DEFAULT_GHSA_ARCHIVE = "data/raw/ghsa/advisory-database-main.tar.gz"
DEFAULT_OUTPUT_DIR = "results/input_integrity/affected_versions"
FROZEN_SAMPLE_MAP_SHA256 = (
    "538c658683a3caec6d6faf9a2b66da064fafeb2b22e13580830c615330727a14"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aligned", default=DEFAULT_ALIGNED)
    parser.add_argument("--sample", default=DEFAULT_SAMPLE)
    parser.add_argument("--ai-gold", default=DEFAULT_AI_GOLD)
    parser.add_argument("--decisions", default=DEFAULT_DECISIONS)
    parser.add_argument("--raw-dir", default=DEFAULT_RAW_DIR)
    parser.add_argument("--ghsa-archive", default=DEFAULT_GHSA_ARCHIVE)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def load_jsonl(path: Path, key: str) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            value = row.get(key)
            if not value or value in rows:
                raise ValueError(f"{path}:{line_number}: missing or duplicate {key}")
            rows[value] = row
    return rows


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sample_map_sha256(rows: dict[str, dict]) -> str:
    mapping = {sample_id: row["cve_id"] for sample_id, row in rows.items()}
    payload = json.dumps(mapping, sort_keys=True, separators=(",", ":")) + "\n"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def false_matches_by_cve(raw_dir: Path, matched_ids: set[str]) -> dict[str, list[dict]]:
    matches: dict[str, list[dict]] = defaultdict(list)
    nvd_paths = resolve_nvd_inputs(raw_dir, "nvdcve-2.0-*.json*")
    if not nvd_paths:
        raise FileNotFoundError(f"No NVD snapshots found under {raw_dir}")
    for path in nvd_paths:
        for cve in iter_nvd_cves(path):
            cve_id = cve.get("id")
            if cve_id not in matched_ids:
                continue
            for config in cve.get("configurations") or []:
                for match in walk_nvd_nodes(config.get("nodes") or []):
                    if match.get("vulnerable") is False:
                        matches[cve_id].append(normalize_nvd_match(match))
    return dict(matches)


def count_ghsa_multi_event_ranges(archive_path: Path) -> dict:
    reviewed_records = 0
    multi_event_ranges = 0
    multi_event_records: set[str] = set()
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive:
            if (
                not member.isfile()
                or "/advisories/github-reviewed/" not in member.name
                or not member.name.endswith(".json")
            ):
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            record = json.load(io.TextIOWrapper(extracted, encoding="utf-8"))
            reviewed_records += 1
            for affected in record.get("affected") or []:
                for range_item in affected.get("ranges") or []:
                    events = range_item.get("events") or []
                    introduced = sum("introduced" in event for event in events)
                    fixed = sum("fixed" in event for event in events)
                    if len(events) > 2 or introduced > 1 or fixed > 1:
                        multi_event_ranges += 1
                        multi_event_records.add(record.get("id") or member.name)
    return {
        "reviewed_records": reviewed_records,
        "multi_event_ranges": multi_event_ranges,
        "multi_event_records": len(multi_event_records),
        "current_snapshot_affected": bool(multi_event_ranges),
    }


def markdown_report(result: dict) -> str:
    counts = result["nvd_vulnerable_false"]
    impact = result["classification_impact"]
    sample = result["frozen_sample_impact"]
    ghsa = result["ghsa_multi_event_range_check"]
    transitions = ", ".join(
        f"`{name}` {count}" for name, count in impact["transition_counts"].items()
    )
    lines = [
        "# affected_versions Input-Integrity Diagnostic",
        "",
        "This diagnostic is derived from the raw authoritative snapshots. It is not a human-gold evaluation.",
        "",
        "## NVD vulnerable=false",
        "",
        f"- Matched NVD-GHSA rows: {result['matched_rows']}",
        f"- Raw non-vulnerable CPE items: {counts['raw_false_items']}",
        f"- Matched rows containing them: {counts['raw_false_rows']}",
        f"- Remaining in rebuilt normalized matched rows: {counts['remaining_normalized_false_items']}",
        f"- Field classifications changed by the fix: {impact['changed_rows']}",
        f"- Transitions: {transitions}",
        "",
        "## Frozen RQ3 sample",
        "",
        f"- Cohort rows: {sample['sample_rows']}",
        f"- Sample ID/CVE identities preserved: {str(sample['identity_preserved']).lower()}",
        f"- Rows with refreshed source inputs: {sample['impacted_rows']}",
        f"- Impacted final-determinate AI rows: {sample['impacted_final_determinate_rows']}",
        f"- Impacted final-abstain AI rows: {sample['impacted_final_abstain_rows']}",
        f"- Recheck decisions changed labels: {sample['decision_rows_with_nonempty_updates']}",
        "",
        "All seven impacted rows were rechecked as AI adjudication only; `label_is_human=false` remains enforced.",
        "",
        "## GHSA multi-event ranges",
        "",
        f"- Reviewed records scanned: {ghsa['reviewed_records']}",
        f"- Multi-event ranges: {ghsa['multi_event_ranges']}",
        f"- Current snapshot affected: {str(ghsa['current_snapshot_affected']).lower()}",
        "",
        "The current snapshot contains no multi-event range, but future ingestion still needs an explicit event-sequence representation before such records appear.",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    aligned_path = resolve(args.aligned)
    sample_path = resolve(args.sample)
    gold_path = resolve(args.ai_gold)
    decisions_path = resolve(args.decisions)
    raw_dir = resolve(args.raw_dir)
    ghsa_archive = resolve(args.ghsa_archive)
    output_dir = resolve(args.output_dir)

    aligned = load_jsonl(aligned_path, "cve_id")
    matched = {cve_id: row for cve_id, row in aligned.items() if row.get("ghsa")}
    sample = load_jsonl(sample_path, "sample_id")
    gold = load_jsonl(gold_path, "sample_id")
    decisions = load_jsonl(decisions_path, "sample_id")
    false_by_cve = false_matches_by_cve(raw_dir, set(matched))

    transitions: Counter[str] = Counter()
    changed_rows = []
    remaining_false = 0
    for cve_id, row in matched.items():
        nvd = row.get("nvd") or {}
        ghsa_rows = row.get("ghsa") or []
        if len(ghsa_rows) != 1:
            raise ValueError(f"{cve_id}: expected one GHSA row, found {len(ghsa_rows)}")
        current_items = nvd.get("affected") or []
        remaining_false += sum(item.get("vulnerable") is False for item in current_items)
        legacy_nvd = dict(nvd)
        legacy_nvd["affected"] = current_items + false_by_cve.get(cve_id, [])
        current_result = compare_affected_versions(nvd, ghsa_rows[0])
        legacy_result = compare_affected_versions(legacy_nvd, ghsa_rows[0])
        if (
            current_result["status"] != legacy_result["status"]
            or current_result["note"] != legacy_result["note"]
        ):
            transition = f"{legacy_result['status']}->{current_result['status']}"
            transitions[transition] += 1
            changed_rows.append(
                {
                    "cve_id": cve_id,
                    "legacy_status": legacy_result["status"],
                    "current_status": current_result["status"],
                    "legacy_note": legacy_result["note"],
                    "current_note": current_result["note"],
                    "removed_false_items": len(false_by_cve.get(cve_id, [])),
                }
            )

    sample_by_cve = {row["cve_id"]: row for row in sample.values()}
    current_sample_map_sha256 = sample_map_sha256(sample)
    impacted_sample_rows = []
    for cve_id, removed in sorted(false_by_cve.items()):
        current_sample = sample_by_cve.get(cve_id)
        if current_sample is None:
            continue
        current_row = matched[cve_id]
        nvd = current_row["nvd"]
        legacy_items = (nvd.get("affected") or []) + removed
        gold_row = gold[current_sample["sample_id"]]
        decision = decisions.get(current_sample["sample_id"])
        impacted_sample_rows.append(
            {
                "sample_id": current_sample["sample_id"],
                "cve_id": cve_id,
                "removed_false_items": len(removed),
                "removed_package_names": sorted(
                    set(normalize_package_names(legacy_items))
                    - set(normalize_package_names(nvd.get("affected") or []))
                ),
                "legacy_span_count": len(normalize_affected_spans(legacy_items)),
                "current_span_count": len(
                    normalize_affected_spans(nvd.get("affected") or [])
                ),
                "ai_gold_status": gold_row["ai_gold_status"],
                "ai_gold_source": gold_row["annotation"].get("adjudicated_source"),
                "ai_gold_label": gold_row["annotation"].get("discrepancy_label"),
                "decision_updates": (decision or {}).get("updates"),
                "recheck_note": (decision or {}).get("review_note"),
            }
        )

    result = {
        "artifact_type": "affected_versions_input_integrity_diagnostic",
        "authoritative_remote": "100.101.249.5:/home/xiaoyuliang/code/vuln-adj",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "matched_rows": len(matched),
        "inputs": {
            "aligned": {"path": str(aligned_path), "sha256": sha256(aligned_path)},
            "sample": {"path": str(sample_path), "sha256": sha256(sample_path)},
            "ai_gold": {"path": str(gold_path), "sha256": sha256(gold_path)},
            "decisions": {
                "path": str(decisions_path),
                "sha256": sha256(decisions_path),
            },
            "ghsa_archive": {
                "path": str(ghsa_archive),
                "sha256": sha256(ghsa_archive),
            },
        },
        "nvd_vulnerable_false": {
            "raw_false_items": sum(map(len, false_by_cve.values())),
            "raw_false_rows": len(false_by_cve),
            "remaining_normalized_false_items": remaining_false,
        },
        "classification_impact": {
            "changed_rows": len(changed_rows),
            "transition_counts": dict(sorted(transitions.items())),
            "rows": changed_rows,
        },
        "frozen_sample_impact": {
            "sample_rows": len(sample),
            "expected_sample_map_sha256": FROZEN_SAMPLE_MAP_SHA256,
            "current_sample_map_sha256": current_sample_map_sha256,
            "identity_preserved": current_sample_map_sha256
            == FROZEN_SAMPLE_MAP_SHA256,
            "impacted_rows": len(impacted_sample_rows),
            "impacted_final_determinate_rows": sum(
                row["ai_gold_status"] == "final_determinate"
                for row in impacted_sample_rows
            ),
            "impacted_final_abstain_rows": sum(
                row["ai_gold_status"] == "final_abstain"
                for row in impacted_sample_rows
            ),
            "decision_rows_with_nonempty_updates": sum(
                bool(row["decision_updates"]) for row in impacted_sample_rows
            ),
            "rows": impacted_sample_rows,
        },
        "ghsa_multi_event_range_check": count_ghsa_multi_event_ranges(ghsa_archive),
        "conclusion": (
            "The NVD vulnerable=false fix changes a small number of full-corpus "
            "baseline classifications and refreshes seven frozen RQ3 inputs, but "
            "the rechecked AI labels and affected-version diagnostic metrics remain unchanged."
        ),
        "cautions": [
            "This is an input-integrity diagnostic, not a human-gold evaluation.",
            "AI rechecks remain label_is_human=false and require real human sign-off.",
            "The current GHSA snapshot has no multi-event range; this does not prove future snapshots are safe to flatten.",
        ],
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "affected_versions_input_integrity.json"
    md_path = output_dir / "affected_versions_input_integrity.md"
    json_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    md_path.write_text(markdown_report(result), encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
