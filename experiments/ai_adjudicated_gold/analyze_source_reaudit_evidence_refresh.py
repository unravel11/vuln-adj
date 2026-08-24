#!/usr/bin/env python3
"""Compare frozen and refreshed evidence for affected-version source re-audit."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OLD = (
    "data/annotations/rq3/silver_v2/"
    "affected_versions_fc_manual_check.evidence.jsonl"
)
DEFAULT_NEW = (
    "data/annotations/ai_adjudicated_gold/source_reaudit/rq3_affected_versions/"
    "evidence_refresh/source_rows.evidence.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/ai_adjudicated_gold/source_reaudit"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old", default=DEFAULT_OLD)
    parser.add_argument("--new", default=DEFAULT_NEW)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--expected-rows", type=int, default=45)
    return parser.parse_args()


def resolve(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_jsonl(path: Path) -> dict[str, dict]:
    rows = {}
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            sample_id = row.get("sample_id")
            if not sample_id or sample_id in rows:
                raise ValueError(
                    f"{path}:{line_number}: missing or duplicate sample_id"
                )
            rows[sample_id] = row
    return rows


def records_by_url(row: dict) -> dict[str, dict]:
    return {
        record["url"]: record
        for record in row.get("evidence_context", {}).get("records", [])
    }


def usable(record: dict) -> bool:
    return record.get("fetch_status") == "ok" and bool(record.get("text_snippet"))


def render_markdown(artifact: dict) -> str:
    lines = [
        "# Affected_versions source re-audit evidence refresh",
        "",
        f"The isolated refresh covers `{artifact['rows']}` selected rows and `{artifact['urls']}` URLs. It does not overwrite the frozen main evidence artifact.",
        "",
        f"Usable URL records changed from `{artifact['old_usable_urls']}` to `{artifact['new_usable_urls']}`. `{artifact['rows_gaining_usable_evidence']}` rows gained usable evidence and `{artifact['rows_losing_usable_evidence']}` lost usable evidence.",
        "",
        "## Status counts",
        "",
        "| Status | Old | Refreshed |",
        "| --- | ---: | ---: |",
    ]
    statuses = sorted(
        set(artifact["old_status_counts"]) | set(artifact["new_status_counts"])
    )
    for status in statuses:
        lines.append(
            f"| `{status}` | {artifact['old_status_counts'].get(status, 0)} | "
            f"{artifact['new_status_counts'].get(status, 0)} |"
        )
    lines.extend(
        [
            "",
            "This is an evidence-availability diagnostic, not source correctness or human validation.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    old_path = resolve(args.old)
    new_path = resolve(args.new)
    output_dir = resolve(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    old = load_jsonl(old_path)
    new = load_jsonl(new_path)
    if len(new) != args.expected_rows or not set(new) <= set(old):
        raise ValueError(
            f"refreshed evidence must select {args.expected_rows} rows "
            "from the frozen 100"
        )

    old_status = Counter()
    new_status = Counter()
    transitions = Counter()
    gains = []
    losses = []
    total_urls = 0
    for sample_id, new_row in new.items():
        old_records = records_by_url(old[sample_id])
        new_records = records_by_url(new_row)
        if set(old_records) != set(new_records):
            raise ValueError(f"{sample_id}: URL identity set changed during refresh")
        total_urls += len(new_records)
        old_usable = sum(usable(record) for record in old_records.values())
        new_usable = sum(usable(record) for record in new_records.values())
        if new_usable > old_usable:
            gains.append(
                {
                    "sample_id": sample_id,
                    "cve_id": new_row.get("cve_id"),
                    "old_usable": old_usable,
                    "new_usable": new_usable,
                }
            )
        elif new_usable < old_usable:
            losses.append(
                {
                    "sample_id": sample_id,
                    "cve_id": new_row.get("cve_id"),
                    "old_usable": old_usable,
                    "new_usable": new_usable,
                }
            )
        for url, new_record in new_records.items():
            before = old_records[url].get("fetch_status", "unknown")
            after = new_record.get("fetch_status", "unknown")
            old_status[before] += 1
            new_status[after] += 1
            transitions[(before, after)] += 1

    artifact = {
        "artifact_type": "affected_versions_source_reaudit_evidence_refresh",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "old_input": {"path": str(old_path), "sha256": sha256(old_path)},
        "new_input": {"path": str(new_path), "sha256": sha256(new_path)},
        "rows": len(new),
        "urls": total_urls,
        "old_usable_urls": sum(
            usable(record)
            for sample_id in new
            for record in records_by_url(old[sample_id]).values()
        ),
        "new_usable_urls": sum(
            usable(record)
            for row in new.values()
            for record in records_by_url(row).values()
        ),
        "old_status_counts": dict(sorted(old_status.items())),
        "new_status_counts": dict(sorted(new_status.items())),
        "status_transitions": [
            {"old": before, "new": after, "count": count}
            for (before, after), count in sorted(transitions.items())
        ],
        "rows_gaining_usable_evidence": len(gains),
        "rows_losing_usable_evidence": len(losses),
        "gain_rows": gains,
        "loss_rows": losses,
        "frozen_main_evidence_modified": False,
        "caution": (
            "Evidence availability does not establish source correctness. "
            "The refreshed snapshot is used only by the isolated re-audit."
        ),
    }
    json_path = output_dir / "affected_versions_source_reaudit_evidence_refresh.json"
    md_path = output_dir / "affected_versions_source_reaudit_evidence_refresh.md"
    json_path.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(artifact), encoding="utf-8")
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
