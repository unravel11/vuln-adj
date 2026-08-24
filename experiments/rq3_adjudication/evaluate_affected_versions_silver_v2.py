#!/usr/bin/env python3
"""Evaluate baseline affected_versions adjudication methods against silver_v2.

This is a silver-label evaluation, not a human-gold result. In addition to the
simple evidence-token baseline, it evaluates conservative package-gated and
parsed-range variants. These variants abstain rather than compare unrelated
package/version systems.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from affected_versions_semantic_baseline import (
    package_gated_token_prediction,
    package_range_evidence_prediction,
    parse_version,
    repository_crosswalk_package_gated_token_prediction,
    token_prediction,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EVIDENCE_INPUT = (
    "data/annotations/rq3/silver_v2/affected_versions_fc_manual_check.evidence.jsonl"
)
DEFAULT_SILVER_INPUT = (
    "data/annotations/rq3/silver_v2/llm_silver_v2/"
    "affected_versions_fc_manual_check.evidence.llm_draft.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/rq3_adjudication"

SOURCE_VALUES = ("nvd", "ghsa", "both", "neither", "abstain")
VERSION_KEYS = (
    "version",
    "version_start_including",
    "version_start_excluding",
    "version_end_including",
    "version_end_excluding",
    "fixed",
    "introduced",
)
VERSION_CANDIDATE_RE = re.compile(
    r"(?<![a-z0-9])v?\d+(?:[._-][a-z0-9]+)+(?![a-z0-9])",
    re.IGNORECASE,
)
VERSION_CLAIM_CUE_RE = re.compile(
    r"\b(?:affected|vulnerab\w*|fixed|fixes|patched|patches|remediat\w*|"
    r"resolved|prior\s+to|before|through|up\s+to|introduced)\b",
    re.IGNORECASE,
)
NON_CLAIM_CONTEXT_RE = re.compile(
    r"\b(?:change\s+history|old\s+value|full\s+changelog|branch\s+selector|"
    r"select\s+branch|showing\s+\d+\s+commits?)\b",
    re.IGNORECASE,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate affected_versions adjudication baselines against silver_v2."
    )
    parser.add_argument("--evidence-input", default=DEFAULT_EVIDENCE_INPUT)
    parser.add_argument("--silver-input", default=DEFAULT_SILVER_INPUT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return (PROJECT_ROOT / path).resolve()


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def load_by_sample_id(path: Path) -> dict[str, dict]:
    rows = {}
    for row in iter_jsonl(path):
        sample_id = row["sample_id"]
        if sample_id in rows:
            raise ValueError(f"Duplicate sample_id in {path}: {sample_id}")
        rows[sample_id] = row
    return rows


def normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().lower()


def extract_version_tokens(spans: list[dict]) -> set[str]:
    tokens = set()
    for span in spans or []:
        for key in VERSION_KEYS:
            value = span.get(key)
            if value is None:
                continue
            token = str(value).strip().lower()
            if token and token not in {"*", "-", "0"}:
                tokens.add(token)
    return tokens


def token_present(text: str, token: str) -> bool:
    if not token:
        return False
    if re.search(rf"(?<![a-z0-9_.-]){re.escape(token)}(?![a-z0-9_.-])", text):
        return True
    if token.startswith(("v", "V")):
        bare = token[1:]
        return bool(
            bare
            and re.search(rf"(?<![a-z0-9_.-]){re.escape(bare)}(?![a-z0-9_.-])", text)
        )
    return False


def canonical_token_present(text: str, token: str) -> bool:
    if token_present(text, token):
        return True
    target = parse_version(token)
    if target is None:
        return False
    for candidate in VERSION_CANDIDATE_RE.findall(text):
        candidate_version = parse_version(candidate.rstrip(".,;:"))
        if candidate_version is None:
            continue
        if (
            candidate_version == target
            and len(candidate_version.release) == len(target.release)
        ):
            return True
    return False


def raw_token_match_spans(text: str, token: str) -> list[tuple[int, int]]:
    candidates = [token]
    if token.startswith(("v", "V")) and len(token) > 1:
        candidates.append(token[1:])
    spans = set()
    for candidate in candidates:
        if not candidate:
            continue
        pattern = re.compile(
            rf"(?<![a-z0-9_.-]){re.escape(candidate)}(?![a-z0-9_.-])",
            re.IGNORECASE,
        )
        spans.update((match.start(), match.end()) for match in pattern.finditer(text))
    return sorted(spans)


def canonical_token_match_spans(text: str, token: str) -> list[tuple[int, int]]:
    spans = set(raw_token_match_spans(text, token))
    target = parse_version(token)
    if target is None:
        return sorted(spans)
    for match in VERSION_CANDIDATE_RE.finditer(text):
        candidate_version = parse_version(match.group(0).rstrip(".,;:"))
        if candidate_version is None:
            continue
        if candidate_version == target and len(candidate_version.release) == len(
            target.release
        ):
            spans.add((match.start(), match.end()))
    return sorted(spans)


def contextual_version_claim_matches(
    text: str,
    token: str,
    cve_id: str,
    *,
    canonical: bool,
) -> list[str]:
    """Return local contexts where a version is tied to an affected/fix claim."""

    normalized_cve = str(cve_id or "").strip().lower()
    if not normalized_cve or normalized_cve not in text.lower():
        return []
    spans = (
        canonical_token_match_spans(text, token)
        if canonical
        else raw_token_match_spans(text, token)
    )
    contexts = []
    for start, end in spans:
        context = text[max(0, start - 240) : min(len(text), end + 240)]
        if not VERSION_CLAIM_CUE_RE.search(context):
            continue
        if NON_CLAIM_CONTEXT_RE.search(context):
            continue
        contexts.append(" ".join(context.split()))
    return contexts


def evidence_support_with_matcher(row: dict, matcher) -> dict[str, dict]:
    tokens_by_source = {
        "nvd": extract_version_tokens(row.get("nvd_value") or []),
        "ghsa": extract_version_tokens(row.get("ghsa_value") or []),
    }
    support = {
        source: {"score": 0, "matched_urls": [], "matched_tokens": []}
        for source in ("nvd", "ghsa")
    }
    seen_matches: set[tuple[str, str, str]] = set()

    for record in row.get("evidence_context", {}).get("records", []):
        if record.get("fetch_status") != "ok" or not record.get("text_snippet"):
            continue
        text = normalize_text(" ".join([record.get("title", ""), record.get("text_snippet", "")]))
        url = record.get("url", "")
        for source, tokens in tokens_by_source.items():
            for token in sorted(tokens):
                if not matcher(text, token):
                    continue
                key = (source, url, token)
                if key in seen_matches:
                    continue
                seen_matches.add(key)
                support[source]["score"] += 1
                support[source]["matched_urls"].append(url)
                support[source]["matched_tokens"].append(token)

    return support


def evidence_support(row: dict) -> dict[str, dict]:
    return evidence_support_with_matcher(row, token_present)


def canonical_evidence_support(row: dict) -> dict[str, dict]:
    return evidence_support_with_matcher(row, canonical_token_present)


def contextual_claim_evidence_support(row: dict, *, canonical: bool) -> dict[str, dict]:
    tokens_by_source = {
        "nvd": extract_version_tokens(row.get("nvd_value") or []),
        "ghsa": extract_version_tokens(row.get("ghsa_value") or []),
    }
    support = {
        source: {
            "score": 0,
            "matched_urls": [],
            "matched_tokens": [],
            "matched_contexts": [],
        }
        for source in ("nvd", "ghsa")
    }
    seen_matches: set[tuple[str, str, str]] = set()
    cve_id = str(row.get("cve_id") or "")
    for record in row.get("evidence_context", {}).get("records", []):
        if record.get("fetch_status") != "ok" or not record.get("text_snippet"):
            continue
        text = normalize_text(
            " ".join([record.get("title", ""), record.get("text_snippet", "")])
        )
        url = record.get("url", "")
        for source, tokens in tokens_by_source.items():
            for token in sorted(tokens):
                contexts = contextual_version_claim_matches(
                    text,
                    token,
                    cve_id,
                    canonical=canonical,
                )
                if not contexts:
                    continue
                key = (source, url, token)
                if key in seen_matches:
                    continue
                seen_matches.add(key)
                support[source]["score"] += 1
                support[source]["matched_urls"].append(url)
                support[source]["matched_tokens"].append(token)
                support[source]["matched_contexts"].append(contexts[0])
    return support


def predict_version_token_support(row: dict) -> dict:
    support = evidence_support(row)
    nvd_supported = support["nvd"]["score"] > 0
    ghsa_supported = support["ghsa"]["score"] > 0

    if nvd_supported and ghsa_supported:
        prediction = "both"
    elif nvd_supported:
        prediction = "nvd"
    elif ghsa_supported:
        prediction = "ghsa"
    else:
        prediction = "abstain"

    return {
        "predicted_source": prediction,
        "support": support,
        "rule": "predict source support when fetched text mentions at least one affected-version token",
    }


def predict_canonical_version_token_support(row: dict) -> dict:
    support = canonical_evidence_support(row)
    return {
        "predicted_source": token_prediction(support),
        "support": support,
        "rule": "predict source support after canonical parsing of version-like evidence tokens",
    }


def predict_contextual_version_claim_support(row: dict) -> dict:
    support = contextual_claim_evidence_support(row, canonical=False)
    return {
        "predicted_source": token_prediction(support),
        "support": support,
        "rule": (
            "predict source support only when an exact version token occurs near an "
            "affected/fix cue on a page containing the target CVE"
        ),
    }


def predict_contextual_canonical_version_claim_support(row: dict) -> dict:
    support = contextual_claim_evidence_support(row, canonical=True)
    return {
        "predicted_source": token_prediction(support),
        "support": support,
        "rule": (
            "predict source support only when an exact or canonical version token "
            "occurs near an affected/fix cue on a page containing the target CVE; "
            "exclude change-history, branch-selector, and full-changelog contexts"
        ),
    }


def predict_package_gated_contextual_version_claim_support(row: dict) -> dict:
    prediction = package_gated_token_prediction(
        row,
        contextual_claim_evidence_support(row, canonical=False),
    )
    prediction["rule"] = (
        "abstain on package mismatch; otherwise require an exact version token near "
        "an affected/fix cue on a page containing the target CVE"
    )
    return prediction


def predict_package_gated_contextual_canonical_version_claim_support(
    row: dict,
) -> dict:
    prediction = package_gated_token_prediction(
        row,
        contextual_claim_evidence_support(row, canonical=True),
    )
    prediction["rule"] = (
        "abstain on package mismatch; otherwise require an exact or canonical "
        "version token near an affected/fix cue on a page containing the target CVE"
    )
    return prediction


def predict_package_gated_token_support(row: dict) -> dict:
    return package_gated_token_prediction(row, evidence_support(row))


def predict_package_gated_canonical_token_support(row: dict) -> dict:
    prediction = package_gated_token_prediction(row, canonical_evidence_support(row))
    prediction["rule"] = (
        "abstain on package mismatch, otherwise use canonical version-token support"
    )
    return prediction


def predict_repository_crosswalk_package_gated_token_support(row: dict) -> dict:
    return repository_crosswalk_package_gated_token_prediction(
        row, evidence_support(row)
    )


def predict_repository_crosswalk_package_gated_canonical_token_support(
    row: dict,
) -> dict:
    prediction = repository_crosswalk_package_gated_token_prediction(
        row, canonical_evidence_support(row)
    )
    prediction["rule"] = (
        "use direct package overlap or a non-conflicting shared-repository "
        "crosswalk before applying canonical version-token support"
    )
    return prediction


def predict_package_range_evidence(row: dict) -> dict:
    return package_range_evidence_prediction(row, evidence_support(row))


def predict_prefer(source: str) -> Callable[[dict], dict]:
    def predictor(row: dict) -> dict:
        return {"predicted_source": source, "rule": f"always prefer {source.upper()}"}

    return predictor


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def predict_latest_published(row: dict) -> dict:
    nvd_time = parse_datetime(row.get("nvd_context", {}).get("published"))
    ghsa_time = parse_datetime(row.get("ghsa_context", {}).get("published"))
    if nvd_time and ghsa_time:
        if nvd_time > ghsa_time:
            prediction = "nvd"
        elif ghsa_time > nvd_time:
            prediction = "ghsa"
        else:
            prediction = "both"
    elif nvd_time:
        prediction = "nvd"
    elif ghsa_time:
        prediction = "ghsa"
    else:
        prediction = "abstain"
    return {
        "predicted_source": prediction,
        "rule": "choose side with later source publication timestamp",
    }


def source_metrics(records: list[dict]) -> dict:
    total = len(records)
    correct = sum(row["predicted_source"] == row["silver_source"] for row in records)
    pred_counts = Counter(row["predicted_source"] for row in records)
    gold_counts = Counter(row["silver_source"] for row in records)
    labels = sorted(set(SOURCE_VALUES) | set(pred_counts) | set(gold_counts))
    per_label = {}
    f1_values = []
    for label in labels:
        tp = sum(
            row["predicted_source"] == label and row["silver_source"] == label
            for row in records
        )
        fp = sum(
            row["predicted_source"] == label and row["silver_source"] != label
            for row in records
        )
        fn = sum(
            row["predicted_source"] != label and row["silver_source"] == label
            for row in records
        )
        precision = safe_divide(tp, tp + fp)
        recall = safe_divide(tp, tp + fn)
        f1 = safe_divide(2 * precision * recall, precision + recall)
        per_label[label] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": gold_counts[label],
            "predicted": pred_counts[label],
        }
        if gold_counts[label]:
            f1_values.append(f1)

    abstained = pred_counts["abstain"]
    covered_records = [row for row in records if row["predicted_source"] != "abstain"]
    covered_correct = sum(
        row["predicted_source"] == row["silver_source"] for row in covered_records
    )
    return {
        "total": total,
        "accuracy": safe_divide(correct, total),
        "macro_f1_over_supported_silver_labels": safe_divide(sum(f1_values), len(f1_values)),
        "coverage_non_abstain": safe_divide(total - abstained, total),
        "accuracy_when_non_abstain": safe_divide(covered_correct, len(covered_records)),
        "predicted_source_counts": dict(sorted(pred_counts.items())),
        "silver_source_counts": dict(sorted(gold_counts.items())),
        "per_label": per_label,
    }


def is_adjudicable_positive(annotation: dict) -> bool:
    return (
        annotation["llm_label"] == "factual_conflict"
        and annotation["adjudicated_source"] in {"nvd", "ghsa"}
        and annotation["confidence"] != "low"
    )


def is_adjudicable_negative(annotation: dict) -> bool:
    return (
        annotation["llm_label"]
        in {"equivalent", "representation_discrepancy", "incomplete"}
        and annotation["is_baseline_false_positive"] == "yes"
        and annotation["adjudicated_source"] in {"nvd", "ghsa", "both"}
        and annotation["confidence"] != "low"
    )


def assign_eval_subset(annotation: dict) -> str:
    if is_adjudicable_positive(annotation):
        return "adjudicable_positive_conflict"
    if is_adjudicable_negative(annotation):
        return "adjudicable_negative_non_conflict"
    return "manual_review_or_excluded"


def candidate_miner_diagnostic(silver_rows: dict[str, dict]) -> dict:
    subset_counts = Counter(
        assign_eval_subset(row["llm_annotation"]) for row in silver_rows.values()
    )
    positive = subset_counts["adjudicable_positive_conflict"]
    negative = subset_counts["adjudicable_negative_non_conflict"]
    excluded = subset_counts["manual_review_or_excluded"]
    adjudicable_total = positive + negative
    return {
        "raw_candidate_source": "all input rows were selected from baseline affected_versions.factual_conflict",
        "adjudicable_positive_conflict": positive,
        "adjudicable_negative_non_conflict": negative,
        "manual_review_or_excluded": excluded,
        "adjudicable_total": adjudicable_total,
        "silver_positive_conflict_rate_among_adjudicable": safe_divide(
            positive, adjudicable_total
        ),
        "silver_negative_non_conflict_rate_among_adjudicable": safe_divide(
            negative, adjudicable_total
        ),
    }


def safe_divide(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def main() -> int:
    args = parse_args()
    evidence_path = resolve_path(args.evidence_input)
    silver_path = resolve_path(args.silver_input)
    output_dir = resolve_path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    evidence_rows = load_by_sample_id(evidence_path)
    silver_rows = load_by_sample_id(silver_path)
    if set(evidence_rows) != set(silver_rows):
        missing_silver = sorted(set(evidence_rows) - set(silver_rows))
        missing_evidence = sorted(set(silver_rows) - set(evidence_rows))
        raise ValueError(
            "Evidence and silver sample_id sets differ: "
            f"missing_silver={missing_silver[:5]}, missing_evidence={missing_evidence[:5]}"
        )

    predictors: dict[str, Callable[[dict], dict]] = {
        "prefer_nvd": predict_prefer("nvd"),
        "prefer_ghsa": predict_prefer("ghsa"),
        "latest_published": predict_latest_published,
        "version_token_support_baseline": predict_version_token_support,
        "canonical_version_token_support_baseline": predict_canonical_version_token_support,
        "contextual_version_claim_baseline": predict_contextual_version_claim_support,
        "contextual_canonical_version_claim_baseline": predict_contextual_canonical_version_claim_support,
        "package_gated_contextual_version_claim_baseline": predict_package_gated_contextual_version_claim_support,
        "package_gated_contextual_canonical_version_claim_baseline": predict_package_gated_contextual_canonical_version_claim_support,
        "package_gated_token_baseline": predict_package_gated_token_support,
        "package_gated_canonical_token_baseline": predict_package_gated_canonical_token_support,
        "repository_crosswalk_package_gated_token_baseline": predict_repository_crosswalk_package_gated_token_support,
        "repository_crosswalk_package_gated_canonical_token_baseline": predict_repository_crosswalk_package_gated_canonical_token_support,
        "package_range_evidence_baseline": predict_package_range_evidence,
    }
    predictions_by_method: dict[str, list[dict]] = {name: [] for name in predictors}

    for sample_id in sorted(evidence_rows):
        row = evidence_rows[sample_id]
        silver_annotation = silver_rows[sample_id]["llm_annotation"]
        silver_source = silver_annotation["adjudicated_source"]
        eval_subset = assign_eval_subset(silver_annotation)
        for method_name, predictor in predictors.items():
            prediction = predictor(row)
            predictions_by_method[method_name].append(
                {
                    "sample_id": sample_id,
                    "cve_id": row["cve_id"],
                    "method": method_name,
                    "silver_source": silver_source,
                    "silver_label": silver_annotation["llm_label"],
                    "is_baseline_false_positive": silver_annotation[
                        "is_baseline_false_positive"
                    ],
                    "confidence": silver_annotation["confidence"],
                    "eval_subset": eval_subset,
                    "predicted_source": prediction["predicted_source"],
                    "is_correct": prediction["predicted_source"] == silver_source,
                    "rule": prediction["rule"],
                    "prediction_detail": {
                        key: value
                        for key, value in prediction.items()
                        if key not in {"predicted_source", "rule"}
                    },
                }
            )

    all_predictions = [
        row for records in predictions_by_method.values() for row in records
    ]
    predictions_path = output_dir / "affected_versions_silver_v2_predictions.jsonl"
    with predictions_path.open("w", encoding="utf-8") as handle:
        for row in all_predictions:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    subset_counts = Counter(
        assign_eval_subset(row["llm_annotation"]) for row in silver_rows.values()
    )
    metrics = {
        "task": "rq3_affected_versions_adjudication_against_silver_v2",
        "evidence_input": str(evidence_path),
        "silver_input": str(silver_path),
        "predictions_path": str(predictions_path),
        "sample_count": len(evidence_rows),
        "silver_label_is_gold": False,
        "eval_subset_counts": dict(sorted(subset_counts.items())),
        "candidate_miner_diagnostic": candidate_miner_diagnostic(silver_rows),
        "adjudicable_subset_definition": {
            "positive_conflict": (
                "llm_label=factual_conflict, adjudicated_source in {nvd, ghsa}, "
                "confidence != low"
            ),
            "negative_non_conflict": (
                "llm_label in {equivalent, representation_discrepancy, incomplete}, "
                "is_baseline_false_positive=yes, adjudicated_source in {nvd, ghsa, both}, "
                "confidence != low"
            ),
            "manual_review_or_excluded": (
                "uncertain, abstain/neither, low confidence, or internally mixed cases"
            ),
        },
        "notes": [
            "Affected_versions metrics are against evidence-aware LLM silver labels, not human gold.",
            "The version_token_support_baseline is a simple text-token baseline, not a semantic version-range adjudicator.",
            "The canonical_version_token_support_baseline additionally parses version-like evidence tokens so representation aliases such as 3.0.0 and 3.0.0.Final can match; it still does not prove range semantics.",
            "The contextual claim baselines additionally require the target CVE and a local affected/fix cue, and reject known change-history, branch-selector, and full-changelog contexts. They remain lexical baselines and do not prove complete range semantics.",
            "The package-gated contextual variants add the existing conservative package-identity gate and therefore trade coverage for abstention on unmapped package/version systems.",
            "The package_gated_token_baseline abstains when package names cannot be aligned.",
            "The package_gated_canonical_token_baseline combines the conservative package gate with canonical version-token matching.",
            "The repository_crosswalk_package_gated_token_baseline additionally accepts a package comparison when both source identifiers anchor to the same non-generic GitHub repository and no package-specific alternative repository conflicts with that bridge.",
            "The repository_crosswalk_package_gated_canonical_token_baseline applies the same repository crosswalk before canonical version-token matching.",
            "The package_range_evidence_baseline only adds a both decision for parseable intervals that are identical after normalization. Immediate-successor boundaries and point-in-range compatibility are diagnostics, not proof of equivalence.",
            "The all-sample source metrics include abstain/neither/uncertain cases; adjudicable subset counts should be used for audit planning.",
        ],
        "methods": {
            method_name: source_metrics(records)
            for method_name, records in predictions_by_method.items()
        },
    }
    metrics_path = output_dir / "affected_versions_silver_v2_eval_metrics.json"
    metrics_path.write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
