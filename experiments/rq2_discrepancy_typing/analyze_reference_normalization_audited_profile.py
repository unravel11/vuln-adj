#!/usr/bin/env python3
"""Evaluate a post-audit reference profile that excludes encoded-line stripping."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from analyze_reference_normalization_variants import (
    VARIANTS,
    evaluate_candidate_dataset,
    evaluate_full_corpus,
    evaluate_repeated_consensus,
    index_candidates,
    load_jsonl,
    source_sample_id,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PRIMARY_SOURCE = "data/annotations/rq2/discrepancy_typing_seed.jsonl"
DEFAULT_REVIEW_SOURCE = (
    "data/annotations/rq2/consistency_review/"
    "discrepancy_typing_consistency_review.jsonl"
)
DEFAULT_PRIMARY_CANDIDATE = "data/annotations/expert_candidate/raw/rq2_primary.jsonl"
DEFAULT_REVIEW_CANDIDATE = "data/annotations/expert_candidate/raw/rq2_review.jsonl"
DEFAULT_FIELD_VIEWS = (
    "data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl"
)
DEFAULT_IMPACT_DIR = (
    "results/rq2_discrepancy_typing/reference_normalization_impact_validation"
)
DEFAULT_COMBINED = f"{DEFAULT_IMPACT_DIR}/reference_normalization_combined_candidate.jsonl"
DEFAULT_EVIDENCE_SUMMARY = (
    f"{DEFAULT_IMPACT_DIR}/reference_normalization_evidence_validation.json"
)
DEFAULT_SEALED_MANIFEST = (
    f"{DEFAULT_IMPACT_DIR}/reference_normalization_impact_manifest.sealed.json"
)
DEFAULT_MERGE_MANIFEST = (
    f"{DEFAULT_IMPACT_DIR}/reference_normalization_merge_manifest.json"
)
DEFAULT_OUTPUT_DIR = (
    "results/rq2_discrepancy_typing/reference_normalization_audited_profile"
)

AUDITED_SETTINGS = {
    "force_https": True,
    "strip_encoded_line_suffix": False,
    "drop_known_presentation_query": True,
    "resource_aliases": True,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--primary-source", default=DEFAULT_PRIMARY_SOURCE)
    parser.add_argument("--review-source", default=DEFAULT_REVIEW_SOURCE)
    parser.add_argument("--primary-candidate", default=DEFAULT_PRIMARY_CANDIDATE)
    parser.add_argument("--review-candidate", default=DEFAULT_REVIEW_CANDIDATE)
    parser.add_argument("--field-views", default=DEFAULT_FIELD_VIEWS)
    parser.add_argument("--combined", default=DEFAULT_COMBINED)
    parser.add_argument("--evidence-summary", default=DEFAULT_EVIDENCE_SUMMARY)
    parser.add_argument("--sealed-manifest", default=DEFAULT_SEALED_MANIFEST)
    parser.add_argument("--merge-manifest", default=DEFAULT_MERGE_MANIFEST)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
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


def verify_manifest(path: Path) -> None:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    for section in ("inputs", "outputs", "code"):
        for item in manifest.get(section, {}).values():
            if not isinstance(item, dict) or "path" not in item or "sha256" not in item:
                continue
            source = Path(item["path"])
            if sha256(source) != item["sha256"]:
                raise ValueError(f"manifest hash mismatch: {source}")


def evaluate_profile(
    primary_sources: list[dict],
    review_sources: list[dict],
    primary_candidates: dict[str, dict],
    review_candidates: dict[str, dict],
    settings: dict[str, bool],
) -> dict:
    primary_by_id = {source_sample_id(row): row for row in primary_sources}
    return {
        "references_primary": evaluate_candidate_dataset(
            primary_sources,
            primary_candidates,
            settings,
            references_only=True,
            expected_rows=60,
        ),
        "references_review": evaluate_candidate_dataset(
            review_sources,
            review_candidates,
            settings,
            references_only=True,
            expected_rows=12,
        ),
        "references_repeated_consensus": evaluate_repeated_consensus(
            primary_by_id,
            primary_candidates,
            review_candidates,
            settings,
            references_only=True,
        ),
        "overall_primary": evaluate_candidate_dataset(
            primary_sources,
            primary_candidates,
            settings,
            references_only=False,
            expected_rows=300,
        ),
        "overall_review": evaluate_candidate_dataset(
            review_sources,
            review_candidates,
            settings,
            references_only=False,
            expected_rows=60,
        ),
        "overall_repeated_consensus": evaluate_repeated_consensus(
            primary_by_id,
            primary_candidates,
            review_candidates,
            settings,
            references_only=False,
        ),
    }


def metric_deltas(current: dict, audited: dict) -> dict:
    result = {}
    for scope in current:
        left = current[scope]
        right = audited[scope]
        delta = {
            "agreement_count": right["agreement_count"] - left["agreement_count"],
            "agreement": right["agreement"] - left["agreement"],
        }
        if "macro_f1_over_supported_candidate_labels" in left:
            delta["macro_f1_over_supported_candidate_labels"] = (
                right["macro_f1_over_supported_candidate_labels"]
                - left["macro_f1_over_supported_candidate_labels"]
            )
            delta["corrections_vs_current"] = len(right["corrections_vs_current"])
            delta["regressions_vs_current"] = len(right["regressions_vs_current"])
        result[scope] = delta
    return result


def validate_impact_alignment(
    combined: list[dict], full_corpus: dict
) -> dict:
    if len(combined) != 56 or len({row["cve_id"] for row in combined}) != 56:
        raise ValueError("combined impact candidate must contain 56 unique CVEs")
    if any(row.get("label_is_human") is not False for row in combined):
        raise ValueError("combined impact rows must remain non-human")
    if any(row.get("requires_human_signoff") is not True for row in combined):
        raise ValueError("combined impact rows must retain the human-signoff gate")
    supported = {
        row["cve_id"]
        for row in combined
        if row["candidate_incomplete_supported"]
    }
    unresolved = {
        row["cve_id"] for row in combined if not row["resolved_nonhuman"]
    }
    changed = set(full_corpus["changed_cve_ids"])
    if changed != supported:
        raise ValueError("audited profile changes do not match strict supported rows")
    if full_corpus["changed_vs_current_transitions"] != {
        "representation_discrepancy->incomplete": len(supported)
    }:
        raise ValueError("audited profile produced an unexpected transition")

    supported_rules = Counter()
    unresolved_rules = Counter()
    for row in combined:
        target = supported_rules if row["cve_id"] in supported else unresolved_rules
        for group in row["automatic_validation"]["proof_required_groups"]:
            target.update(group["structural_eligibility"]["rules"])
    return {
        "strict_supported_rows": len(supported),
        "unresolved_rows": len(unresolved),
        "changed_set_exactly_matches_strict_supported_rows": True,
        "strict_supported_rule_counts": dict(sorted(supported_rules.items())),
        "unresolved_rule_counts": dict(sorted(unresolved_rules.items())),
        "changed_cve_ids": full_corpus["changed_cve_ids"],
    }


def render_markdown(result: dict) -> str:
    current = result["candidate_diagnostic"]["current"]
    audited = result["candidate_diagnostic"]["audited"]
    lines = [
        "# Reference Normalization Audited Development Profile",
        "",
        "> Post-audit, non-human development diagnostic; not confirmatory evidence.",
        "",
        f"- Full-corpus changes: `{result['full_corpus']['changed_vs_current_count']}/8066`",
        f"- Strict dual-review support: `{result['impact_alignment']['strict_supported_rows']}/56`",
        f"- Unresolved encoded-line rows: `{result['impact_alignment']['unresolved_rows']}/56`",
        f"- Changed set equals strict supported set: `{result['impact_alignment']['changed_set_exactly_matches_strict_supported_rows']}`",
        "",
        "| Scope | Current | Audited | Delta |",
        "|---|---:|---:|---:|",
    ]
    for scope in ("references_primary", "references_review", "overall_primary", "overall_review"):
        left = current[scope]
        right = audited[scope]
        lines.append(
            f"| {scope} | {left['agreement_count']}/{left['determinate_rows']} ({left['agreement']:.4f}) | "
            f"{right['agreement_count']}/{right['determinate_rows']} ({right['agreement']:.4f}) | "
            f"{right['agreement'] - left['agreement']:+.4f} |"
        )
    lines.extend(
        [
            "",
            "The profile retains HTTPS normalization, scoped Liferay query removal, and exact GHSA/Huntr identifier aliases, but does not strip encoded GitHub line suffixes.",
            "",
            "Production default changed: `false`. Real-human signed rows: `0`.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    paths = {
        name: resolve(value)
        for name, value in {
            "primary_source": args.primary_source,
            "review_source": args.review_source,
            "primary_candidate": args.primary_candidate,
            "review_candidate": args.review_candidate,
            "field_views": args.field_views,
            "combined": args.combined,
            "evidence_summary": args.evidence_summary,
            "sealed_manifest": args.sealed_manifest,
            "merge_manifest": args.merge_manifest,
        }.items()
    }
    output_dir = resolve(args.output_dir)
    verify_manifest(paths["sealed_manifest"])
    verify_manifest(paths["merge_manifest"])

    primary_sources = load_jsonl(paths["primary_source"])
    review_sources = load_jsonl(paths["review_source"])
    primary_candidates = index_candidates(
        load_jsonl(paths["primary_candidate"]), expected_rows=300
    )
    review_candidates = index_candidates(
        load_jsonl(paths["review_candidate"]), expected_rows=60
    )
    field_views = load_jsonl(paths["field_views"])
    if len(field_views) != 8066:
        raise ValueError(f"expected 8066 field views, found {len(field_views)}")

    evidence = json.loads(paths["evidence_summary"].read_text(encoding="utf-8"))
    if (
        evidence.get("secondary_strict_rows") != 32
        or evidence.get("combined_resolved_status_counts")
        != {"incomplete": 32, "unresolved": 24}
        or evidence.get("human_signed_rows") != 0
    ):
        raise ValueError("unexpected evidence-validation gate")
    combined = load_jsonl(paths["combined"])

    current = evaluate_profile(
        primary_sources,
        review_sources,
        primary_candidates,
        review_candidates,
        VARIANTS["current_exact"],
    )
    audited = evaluate_profile(
        primary_sources,
        review_sources,
        primary_candidates,
        review_candidates,
        AUDITED_SETTINGS,
    )
    full_corpus = evaluate_full_corpus(field_views, AUDITED_SETTINGS)
    impact_alignment = validate_impact_alignment(combined, full_corpus)
    result = {
        "artifact_type": "rq2_reference_normalization_audited_development_profile",
        "profile": "resource_identity_audited_v1",
        "settings": AUDITED_SETTINGS,
        "post_audit_profile_selection": True,
        "selection_rule": (
            "Retain transformations with strict two-run consensus across their "
            "complete impact rows; exclude encoded-line stripping because all 24 "
            "affected rows were reviewer disagreements."
        ),
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_confirmatory_claim": False,
        "production_default_changed": False,
        "human_signed_rows": 0,
        "impact_alignment": impact_alignment,
        "candidate_diagnostic": {
            "current": current,
            "audited": audited,
            "audited_minus_current": metric_deltas(current, audited),
        },
        "full_corpus": full_corpus,
        "cautions": [
            "The profile was selected after inspecting the full-impact dual-review result.",
            "Candidate agreement uses same-model AI labels and is not human-gold accuracy.",
            "The 32 changed rows are a complete rule-impact set, not a representative sample.",
            "No inferential significance claim is made from these development diagnostics.",
        ],
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "reference_normalization_audited_profile.json"
    markdown_path = output_dir / "reference_normalization_audited_profile.md"
    manifest_path = output_dir / "reference_normalization_audited_profile_manifest.json"
    json_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render_markdown(result), encoding="utf-8")
    manifest = {
        "artifact_type": "reference_normalization_audited_profile_manifest",
        "label_is_human": False,
        "inputs": {
            name: {"path": str(path), "sha256": sha256(path)}
            for name, path in paths.items()
        },
        "outputs": {
            "json": {"path": str(json_path), "sha256": sha256(json_path)},
            "markdown": {
                "path": str(markdown_path),
                "sha256": sha256(markdown_path),
            },
        },
        "code": {
            "path": str(Path(__file__).resolve()),
            "sha256": sha256(Path(__file__).resolve()),
        },
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {json_path}")
    print(f"Wrote {markdown_path}")
    print(json.dumps(full_corpus["changed_vs_current_transitions"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
