#!/usr/bin/env python3
"""Seal structural and live-HTTP validation for all 56 reference-rule changes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import ssl
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from difflib import SequenceMatcher
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

from analyze_reference_normalization_variants import (
    GHSA_PATH_RE,
    HUNTR_PATH_RE,
    LINE_SUFFIX_RE,
    VARIANTS,
    canonicalize_reference_url,
    classify_references,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_WORKLIST = (
    "results/rq2_discrepancy_typing/"
    "reference_normalization_changed_cases.review.jsonl"
)
DEFAULT_VARIANT_DIAGNOSTIC = (
    "results/rq2_discrepancy_typing/"
    "reference_normalization_variant_diagnostic.json"
)
DEFAULT_DUAL_REVIEW = (
    "results/rq2_discrepancy_typing/reference_normalization_dual_ai_review.json"
)
DEFAULT_PROMPT = "docs/prompts/rq2_reference_identity_evidence_review.md"
DEFAULT_PROMPT_E = "docs/prompts/rq2_reference_identity_reviewer_e.md"
DEFAULT_PROMPT_F = "docs/prompts/rq2_reference_identity_reviewer_f.md"
DEFAULT_MERGE_CODE = (
    "experiments/rq2_discrepancy_typing/"
    "merge_reference_normalization_impact_validation.py"
)
DEFAULT_OUTPUT_DIR = (
    "results/rq2_discrepancy_typing/reference_normalization_impact_validation"
)
DEFAULT_SUPERSEDED_PILOT_MANIFEST = (
    "results/rq2_discrepancy_typing/"
    "reference_normalization_impact_validation_superseded_hidden_contract/"
    "reference_normalization_impact_manifest.sealed.json"
)
DEFAULT_CACHE_DIR = (
    "data/evidence_cache/rq2/reference_normalization_identity/url_cache"
)
DEFAULT_AGENT_E = (
    "data/annotations/expert_candidate/batches/"
    "rq2_reference_identity_agent_e.jsonl"
)
DEFAULT_AGENT_F = (
    "data/annotations/expert_candidate/batches/"
    "rq2_reference_identity_agent_f.jsonl"
)
DEFAULT_TIMEOUT_SECONDS = 15
DEFAULT_MAX_BYTES = 750_000
DEFAULT_MAX_TEXT_CHARS = 6_000
DEFAULT_CACHE_MAX_AGE_SECONDS = 86_400
PROBE_SCHEMA_VERSION = "rq2_reference_probe_v2"
TRANSIENT_STATUSES = {
    "timeout",
    "url_error",
    "probe_error",
    "http_429",
    "http_500",
    "http_502",
    "http_503",
    "http_504",
}


class TextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.skip_depth = 0
        self.in_title = False
        self.title_parts: list[str] = []
        self.text_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.lower()
        if tag in {"script", "style", "noscript", "svg"}:
            self.skip_depth += 1
        if tag == "title":
            self.in_title = True

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in {"script", "style", "noscript", "svg"} and self.skip_depth:
            self.skip_depth -= 1
        if tag == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        text = normalize_whitespace(data)
        if not text:
            return
        if self.in_title:
            self.title_parts.append(text)
        if not self.skip_depth:
            self.text_parts.append(text)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worklist", default=DEFAULT_WORKLIST)
    parser.add_argument("--variant-diagnostic", default=DEFAULT_VARIANT_DIAGNOSTIC)
    parser.add_argument("--dual-review", default=DEFAULT_DUAL_REVIEW)
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--prompt-e", default=DEFAULT_PROMPT_E)
    parser.add_argument("--prompt-f", default=DEFAULT_PROMPT_F)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--superseded-pilot-manifest",
        default=DEFAULT_SUPERSEDED_PILOT_MANIFEST,
    )
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR)
    parser.add_argument("--agent-e", default=DEFAULT_AGENT_E)
    parser.add_argument("--agent-f", default=DEFAULT_AGENT_F)
    parser.add_argument("--timeout-seconds", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--refresh", action="store_true")
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


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{line_number}") from exc


def write_jsonl(path: Path, rows: list[dict]) -> None:
    atomic_write_text(
        path,
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
    )


def atomic_write_text(path: Path, value: str) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(value, encoding="utf-8")
    temporary.replace(path)


def normalize_whitespace(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def cache_path(cache_dir: Path, url: str) -> Path:
    return cache_dir / f"{hashlib.sha256(url.encode()).hexdigest()}.json"


def decode_text(body: bytes, content_type: str) -> tuple[str, str]:
    charset = "utf-8"
    match = re.search(r"charset=([^;\s]+)", content_type, re.IGNORECASE)
    if match:
        charset = match.group(1).strip("\"'")
    raw = body.decode(charset, errors="replace")
    if "html" not in content_type.lower():
        return "", normalize_whitespace(raw)
    parser = TextParser()
    parser.feed(raw)
    return (
        normalize_whitespace(" ".join(parser.title_parts)),
        normalize_whitespace(" ".join(parser.text_parts)),
    )


def error_record(
    url: str,
    status: str,
    detail: str,
    final_url: str = "",
    http_status: int | None = None,
) -> dict:
    return {
        "schema_version": PROBE_SCHEMA_VERSION,
        "url": url,
        "final_url": final_url,
        "redirected": bool(final_url and final_url != url),
        "status": status,
        "http_status": http_status,
        "content_type": "",
        "title": "",
        "text_snippet": "",
        "body_sha256": None,
        "text_sha256": None,
        "truncated": False,
        "captured_bytes": 0,
        "declared_content_length": None,
        "detail": detail[:300],
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def probe_url(url: str, timeout_seconds: int) -> dict:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        return error_record(url, "unsupported_scheme", parsed.scheme)
    request = Request(
        url,
        headers={
            "User-Agent": "vuln-adj-reference-identity-validator/0.1",
            "Accept": "text/html,text/plain,application/json;q=0.9,*/*;q=0.1",
        },
    )
    try:
        with urlopen(
            request,
            timeout=timeout_seconds,
            context=ssl.create_default_context(),
        ) as response:
            captured = response.read(DEFAULT_MAX_BYTES + 1)
            truncated = len(captured) > DEFAULT_MAX_BYTES
            body = captured[:DEFAULT_MAX_BYTES]
            content_type = response.headers.get("Content-Type", "")
            title, text = decode_text(body, content_type)
            return {
                "schema_version": PROBE_SCHEMA_VERSION,
                "url": url,
                "final_url": response.geturl(),
                "redirected": response.geturl() != url,
                "status": "ok",
                "http_status": response.status,
                "content_type": content_type,
                "title": title,
                "text_snippet": text[:DEFAULT_MAX_TEXT_CHARS],
                "body_sha256": None if truncated else sha256_bytes(body),
                "text_sha256": None if truncated else sha256_bytes(text.encode()),
                "truncated": truncated,
                "captured_bytes": len(body),
                "declared_content_length": response.headers.get("Content-Length"),
                "detail": f"bytes={len(body)}",
                "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
    except HTTPError as exc:
        return error_record(
            url,
            f"http_{exc.code}",
            str(exc),
            exc.geturl(),
            exc.code,
        )
    except URLError as exc:
        return error_record(url, "url_error", str(exc.reason))
    except TimeoutError as exc:
        return error_record(url, "timeout", str(exc))
    except Exception as exc:
        return error_record(url, "probe_error", f"{type(exc).__name__}: {exc}")


def load_or_probe(
    url: str,
    cache_dir: Path,
    timeout_seconds: int,
    refresh: bool,
) -> tuple[dict, bool]:
    path = cache_path(cache_dir, url)
    if path.exists() and not refresh:
        try:
            cached = json.loads(path.read_text(encoding="utf-8"))
            fetched_at = datetime.strptime(
                cached["fetched_at"], "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc).timestamp()
            valid = (
                cached.get("schema_version") == PROBE_SCHEMA_VERSION
                and cached.get("url") == url
                and cached.get("status") not in TRANSIENT_STATUSES
                and time.time() - fetched_at <= DEFAULT_CACHE_MAX_AGE_SECONDS
            )
            if valid:
                return cached, True
        except (KeyError, ValueError, json.JSONDecodeError):
            pass
    record = error_record(url, "probe_error", "probe did not run")
    attempt_count = 0
    for attempt_count in range(1, 4):
        record = probe_url(url, timeout_seconds)
        if record["status"] not in TRANSIENT_STATUSES:
            break
        if attempt_count < 3:
            time.sleep(0.5 * attempt_count)
    record["attempt_count"] = attempt_count
    atomic_write_text(
        path,
        json.dumps(record, ensure_ascii=False, indent=2) + "\n",
    )
    time.sleep(0.1)
    return record, False


def identity_groups(row: dict) -> list[dict]:
    entries = []
    for side, key in (("nvd", "nvd_urls"), ("ghsa", "ghsa_urls")):
        for url in row[key]:
            entries.append(
                {
                    "side": side,
                    "url": url,
                    "current_identity": canonicalize_reference_url(
                        url, VARIANTS["current_exact"]
                    ),
                    "proposed_identity": canonicalize_reference_url(
                        url, VARIANTS["transport_line_known_query_aliases"]
                    ),
                }
            )
    grouped = defaultdict(list)
    for entry in entries:
        grouped[entry["proposed_identity"]].append(entry)
    result = []
    for proposed_identity, members in sorted(grouped.items()):
        current = sorted({member["current_identity"] for member in members})
        result.append(
            {
                "proposed_identity": proposed_identity,
                "proof_required": len(current) > 1,
                "current_identities": current,
                "sides": sorted({member["side"] for member in members}),
                "members": members,
            }
        )
    return result


def transformed_rules(url: str) -> list[str]:
    stages = [
        "current_exact",
        "transport_and_line",
        "transport_line_known_query",
        "transport_line_known_query_aliases",
    ]
    values = {
        stage: canonicalize_reference_url(url, VARIANTS[stage]) for stage in stages
    }
    parsed = urlsplit(url)
    rules = []
    if values["current_exact"] != values["transport_and_line"]:
        if parsed.scheme.lower() == "http":
            rules.append("transport_upgrade")
        if LINE_SUFFIX_RE.search(parsed.path):
            rules.append("encoded_line_suffix")
    if values["transport_and_line"] != values["transport_line_known_query"]:
        rules.append("known_presentation_query")
    if (
        values["transport_line_known_query"]
        != values["transport_line_known_query_aliases"]
    ):
        proposed = values["transport_line_known_query_aliases"]
        if proposed.startswith("github-advisory:"):
            rules.append("github_advisory_alias")
        elif proposed.startswith("huntr-bounty:"):
            rules.append("huntr_bounty_alias")
        else:
            rules.append("unknown_resource_alias")
    return rules


def structural_eligibility(group: dict) -> dict:
    rules = sorted(
        {
            rule
            for member in group["members"]
            for rule in transformed_rules(member["url"])
        }
    )
    checks = {}
    for rule in rules:
        affected = [
            member for member in group["members"] if rule in transformed_rules(member["url"])
        ]
        if rule == "transport_upgrade":
            checks[rule] = all(urlsplit(item["url"]).scheme.lower() == "http" for item in affected)
        elif rule == "encoded_line_suffix":
            checks[rule] = all(
                urlsplit(item["url"]).netloc.lower() == "github.com"
                and "/blob/" in urlsplit(item["url"]).path
                and LINE_SUFFIX_RE.search(urlsplit(item["url"]).path)
                for item in affected
            )
        elif rule == "known_presentation_query":
            checks[rule] = all(
                urlsplit(item["url"]).netloc.lower() == "liferay.dev"
                and "/known-vulnerabilities/" in urlsplit(item["url"]).path.lower()
                and "/content/cve-" in urlsplit(item["url"]).path.lower()
                for item in affected
            )
        elif rule == "github_advisory_alias":
            identifiers = {
                GHSA_PATH_RE.search(urlsplit(item["url"]).path).group(1).lower()
                for item in affected
                if GHSA_PATH_RE.search(urlsplit(item["url"]).path)
            }
            checks[rule] = len(identifiers) == 1 and group["proposed_identity"] == (
                f"github-advisory:{next(iter(identifiers))}" if identifiers else ""
            )
        elif rule == "huntr_bounty_alias":
            identifiers = {
                HUNTR_PATH_RE.fullmatch(urlsplit(item["url"]).path).group(1).lower()
                for item in affected
                if HUNTR_PATH_RE.fullmatch(urlsplit(item["url"]).path)
            }
            checks[rule] = len(identifiers) == 1 and group["proposed_identity"] == (
                f"huntr-bounty:{next(iter(identifiers))}" if identifiers else ""
            )
        else:
            checks[rule] = False
    return {
        "rules": rules,
        "checks": checks,
        "eligible": bool(rules) and all(checks.values()),
    }


def normalized_final_url(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path,
            parsed.query,
            "",
        )
    )


def text_similarity(left: dict, right: dict) -> float:
    if not usable_content_record(left) or not usable_content_record(right):
        return 0.0
    left_text = left.get("text_snippet") or ""
    right_text = right.get("text_snippet") or ""
    if not left_text or not right_text:
        return 0.0
    return SequenceMatcher(None, left_text, right_text).ratio()


def usable_content_record(record: dict) -> bool:
    if record.get("status") != "ok" or record.get("truncated"):
        return False
    text = f"{record.get('title', '')} {record.get('text_snippet', '')}".lower()
    generic_markers = (
        "just a moment",
        "attention required",
        "access denied",
        "rate limit exceeded",
        "verify you are human",
    )
    return len(text.strip()) >= 80 and not any(
        marker in text for marker in generic_markers
    )


def network_certificate(group: dict, probes: dict[str, dict]) -> dict:
    records_by_identity = defaultdict(list)
    for member in group["members"]:
        records_by_identity[member["current_identity"]].append(probes[member["url"]])
    ok_by_identity = {
        identity: [record for record in records if record.get("status") == "ok"]
        for identity, records in records_by_identity.items()
    }
    all_identities_live = all(ok_by_identity.values())
    final_sets = [
        {normalized_final_url(record["final_url"]) for record in records}
        for records in ok_by_identity.values()
    ]
    body_sets = [
        {
            record["body_sha256"]
            for record in records
            if usable_content_record(record) and record.get("body_sha256")
        }
        for records in ok_by_identity.values()
    ]
    shared_final = (
        set.intersection(*final_sets) if all_identities_live and final_sets else set()
    )
    shared_body = (
        set.intersection(*body_sets)
        if all_identities_live and body_sets and all(body_sets)
        else set()
    )
    pairwise_similarities = []
    identities = sorted(ok_by_identity)
    for left_index, left_identity in enumerate(identities):
        for right_identity in identities[left_index + 1 :]:
            pairwise_similarities.append(
                max(
                    (
                        text_similarity(left, right)
                        for left in ok_by_identity[left_identity]
                        for right in ok_by_identity[right_identity]
                    ),
                    default=0.0,
                )
            )
    minimum_pairwise_similarity = min(pairwise_similarities, default=0.0)
    identity = group["proposed_identity"].lower()
    expected_token = identity.split(":", 1)[1] if ":" in identity else ""
    identifier_identity_hits = sum(
        any(
            expected_token
            and expected_token
            in (
                f"{record.get('title', '')} {record.get('text_snippet', '')}"
            ).lower()
            and usable_content_record(record)
            for record in records
        )
        for records in ok_by_identity.values()
    )
    rules = structural_eligibility(group)["rules"]
    supported = False
    reason = "no_live_corroboration"
    if shared_final:
        supported, reason = True, "same_final_url"
    elif shared_body:
        supported, reason = True, "same_content_fingerprint"
    elif (
        all_identities_live
        and any(
            rule in rules
            for rule in ("github_advisory_alias", "huntr_bounty_alias")
        )
        and identifier_identity_hits == len(ok_by_identity)
    ):
        supported, reason = True, "same_resource_identifier_observed"
    return {
        "supported": supported,
        "reason": reason,
        "identity_count": len(ok_by_identity),
        "live_identity_count": sum(bool(records) for records in ok_by_identity.values()),
        "ok_records": sum(len(records) for records in ok_by_identity.values()),
        "shared_final_url": sorted(shared_final),
        "shared_body_sha256": sorted(shared_body),
        "minimum_pairwise_text_similarity": round(
            minimum_pairwise_similarity, 6
        ),
        "text_similarity_is_diagnostic_only": True,
        "identifier_identity_hits": identifier_identity_hits,
    }


def build_row(row: dict, probes: dict[str, dict], index: int) -> dict:
    groups = identity_groups(row)
    proof_groups = []
    for group in groups:
        if not group["proof_required"]:
            continue
        group = dict(group)
        group["structural_eligibility"] = structural_eligibility(group)
        group["network_certificate"] = network_certificate(group, probes)
        group["probe_records"] = [probes[member["url"]] for member in group["members"]]
        proof_groups.append(group)

    proposed_nvd = set(row["proposed_normalized_nvd"])
    proposed_ghsa = set(row["proposed_normalized_ghsa"])
    strict_subset = proposed_nvd < proposed_ghsa or proposed_ghsa < proposed_nvd
    if row["current_status"] != "representation_discrepancy" or row["proposed_status"] != "incomplete":
        raise ValueError(f"unexpected transition for {row['cve_id']}")
    if not strict_subset or not proof_groups:
        raise ValueError(f"missing subset/proof group for {row['cve_id']}")
    structural = all(group["structural_eligibility"]["eligible"] for group in proof_groups)
    network = structural and all(
        group["network_certificate"]["supported"] for group in proof_groups
    )
    status = (
        "network_corroborated"
        if network
        else "structural_eligible_only"
        if structural
        else "structural_ineligible"
    )
    return {
        "review_id": f"rq2_reference_identity:{index:03d}",
        "cve_id": row["cve_id"],
        "field": "references",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "trigger_stage": row["trigger_stage"],
        "current_status": row["current_status"],
        "proposed_status": row["proposed_status"],
        "proposed_subset_side": "nvd" if proposed_nvd < proposed_ghsa else "ghsa",
        "proof_required_groups": proof_groups,
        "structural_eligible": structural,
        "network_corroborated": network,
        "validation_status": status,
    }


def masked_secondary_row(row: dict) -> dict:
    groups = []
    for group_index, source in enumerate(row["proof_required_groups"], start=1):
        groups.append(
            {
                "group_id": f"{row['review_id']}:group:{group_index:02d}",
                "members": [
                    {"side": member["side"], "url": member["url"]}
                    for member in source["members"]
                ],
                "probe_records": source["probe_records"],
            }
        )
    return {
        "review_id": row["review_id"],
        "cve_id": row["cve_id"],
        "field": row["field"],
        "identity_groups": groups,
        "review_contract": {
            "identity_verdict": [
                "all_aliases_same_resource",
                "one_or_more_not_same",
                "insufficient",
            ],
            "final_status": [
                "incomplete",
                "representation_discrepancy",
                "uncertain",
            ],
            "confidence": ["high", "medium", "low"],
        },
    }


def render_markdown(summary: dict) -> str:
    return "\n".join(
        [
            "# Reference Normalization Full-Impact Identity Validation",
            "",
            "> Structural/live-network diagnostic only; not human gold.",
            "",
            f"- Rows: `{summary['row_count']}`",
            f"- Proof-required identity groups: `{summary['proof_required_groups']}`",
            f"- Network-corroborated rows: `{summary['validation_status_counts'].get('network_corroborated', 0)}`",
            f"- Structural-eligible-only rows: `{summary['validation_status_counts'].get('structural_eligible_only', 0)}`",
            f"- Structural-ineligible rows: `{summary['validation_status_counts'].get('structural_ineligible', 0)}`",
            f"- Secondary-review rows: `{summary['secondary_review_rows']}`",
            "",
            "All 56 impact rows enter two transformation-masked, prior-label-blind non-human reviews; network certificates are auxiliary evidence only.",
            "",
        ]
    )


def validate_source_rows(rows: list[dict], diagnostic: dict) -> dict:
    cve_ids = [row.get("cve_id") for row in rows]
    if len(cve_ids) != len(set(cve_ids)):
        raise ValueError("changed-case CVE IDs must be unique")
    full = diagnostic["variants"]["transport_line_known_query_aliases"][
        "full_corpus"
    ]
    expected_cves = full["changed_cve_ids"]
    if len(rows) != full["changed_vs_current_count"]:
        raise ValueError("changed-case count differs from variant diagnostic")
    if set(cve_ids) != set(expected_cves):
        raise ValueError("changed-case CVE set differs from variant diagnostic")
    expected_transition = {"representation_discrepancy->incomplete": len(rows)}
    if full["changed_vs_current_transitions"] != expected_transition:
        raise ValueError("unexpected full-impact transition in variant diagnostic")

    trigger_counts = Counter()
    stages = (
        "transport_and_line",
        "transport_line_known_query",
        "transport_line_known_query_aliases",
    )
    for row in rows:
        recomputed = {}
        for stage in ("current_exact", *stages):
            settings = VARIANTS[stage]
            recomputed[stage] = {
                "nvd": sorted(
                    {
                        canonicalize_reference_url(url, settings)
                        for url in row["nvd_urls"]
                    }
                ),
                "ghsa": sorted(
                    {
                        canonicalize_reference_url(url, settings)
                        for url in row["ghsa_urls"]
                    }
                ),
                "status": classify_references(
                    row["nvd_urls"], row["ghsa_urls"], settings
                ),
            }
        checks = {
            "current_normalized_nvd": recomputed["current_exact"]["nvd"],
            "current_normalized_ghsa": recomputed["current_exact"]["ghsa"],
            "proposed_normalized_nvd": recomputed[
                "transport_line_known_query_aliases"
            ]["nvd"],
            "proposed_normalized_ghsa": recomputed[
                "transport_line_known_query_aliases"
            ]["ghsa"],
            "current_status": recomputed["current_exact"]["status"],
            "proposed_status": recomputed[
                "transport_line_known_query_aliases"
            ]["status"],
        }
        for key, expected in checks.items():
            if row.get(key) != expected:
                raise ValueError(f"stale derived field for {row['cve_id']}: {key}")
        current_status = recomputed["current_exact"]["status"]
        trigger_stage = next(
            (
                stage
                for stage in stages
                if recomputed[stage]["status"] != current_status
            ),
            None,
        )
        if trigger_stage != row.get("trigger_stage"):
            raise ValueError(f"trigger-stage mismatch for {row['cve_id']}")
        trigger_counts[trigger_stage] += 1

    worklist_summary = diagnostic["changed_case_worklist"]
    if worklist_summary["row_count"] != len(rows):
        raise ValueError("worklist row count differs from diagnostic")
    if worklist_summary["trigger_stage_counts"] != dict(sorted(trigger_counts.items())):
        raise ValueError("trigger-stage counts differ from diagnostic")
    return {
        "unique_cves": len(set(cve_ids)),
        "variant_changed_cves_exact_match": True,
        "derived_fields_recomputed": True,
        "trigger_stage_counts": dict(sorted(trigger_counts.items())),
    }


def build(args: argparse.Namespace) -> int:
    paths = {
        "worklist": resolve(args.worklist),
        "variant_diagnostic": resolve(args.variant_diagnostic),
        "dual_review": resolve(args.dual_review),
        "prompt": resolve(args.prompt),
        "prompt_e": resolve(args.prompt_e),
        "prompt_f": resolve(args.prompt_f),
        "merge_code": resolve(DEFAULT_MERGE_CODE),
        "normalizer_code": resolve("experiments/rq2_discrepancy_typing/analyze_reference_normalization_variants.py"),
        "superseded_pilot_manifest": resolve(args.superseded_pilot_manifest),
        "agent_e": resolve(args.agent_e),
        "agent_f": resolve(args.agent_f),
    }
    if paths["agent_e"].exists() or paths["agent_f"].exists():
        raise ValueError("reference identity reviewer output exists before sealing")
    output_dir = resolve(args.output_dir)
    cache_dir = resolve(args.cache_dir)
    row_path = output_dir / "reference_normalization_identity_validation.jsonl"
    probe_path = output_dir / "reference_normalization_probe_records.jsonl"
    masked_path = output_dir / "reference_identity_secondary_worklist.masked.jsonl"
    summary_path = output_dir / "reference_normalization_impact_validation.json"
    markdown_path = output_dir / "reference_normalization_impact_validation.md"
    manifest_path = output_dir / "reference_normalization_impact_manifest.sealed.json"
    outputs = (
        row_path,
        probe_path,
        masked_path,
        summary_path,
        markdown_path,
        manifest_path,
    )
    if not args.force and any(path.exists() for path in outputs):
        raise ValueError("reference impact validation output already exists")

    source_rows = list(iter_jsonl(paths["worklist"]))
    if len(source_rows) != 56:
        raise ValueError(f"expected 56 changed rows, found {len(source_rows)}")
    diagnostic = json.loads(paths["variant_diagnostic"].read_text(encoding="utf-8"))
    source_validation = validate_source_rows(source_rows, diagnostic)
    dual_review = json.loads(paths["dual_review"].read_text(encoding="utf-8"))
    if dual_review.get("row_count") != 56:
        raise ValueError("dual-review row count differs from full impact set")
    input_hashes = {
        name: sha256(path)
        for name, path in paths.items()
        if name not in {"agent_e", "agent_f"}
    }
    builder_path = Path(__file__).resolve()
    builder_hash = sha256(builder_path)
    urls = sorted(
        {
            member["url"]
            for row in source_rows
            for group in identity_groups(row)
            if group["proof_required"]
            for member in group["members"]
        }
    )
    cache_dir.mkdir(parents=True, exist_ok=True)
    probes = {}
    cache_hits = 0
    for url in urls:
        record, from_cache = load_or_probe(
            url, cache_dir, args.timeout_seconds, args.refresh
        )
        probes[url] = record
        cache_hits += int(from_cache)

    rows = [build_row(row, probes, index) for index, row in enumerate(source_rows, 1)]
    secondary = rows
    summary = {
        "artifact_type": "reference_normalization_full_impact_identity_validation",
        "review_protocol_revision": 2,
        "superseded_pilot_excluded": True,
        "protocol_repair_reason": (
            "The pilot validator enforced confidence/additional-review constraints "
            "that were absent from its sealed reviewer prompt."
        ),
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_confirmatory_claim": False,
        "row_count": len(rows),
        "unique_probe_urls": len(urls),
        "cache_hits": cache_hits,
        "cache_misses": len(urls) - cache_hits,
        "source_validation": source_validation,
        "probe_status_counts": dict(sorted(Counter(row["status"] for row in probes.values()).items())),
        "proof_required_groups": sum(len(row["proof_required_groups"]) for row in rows),
        "proof_group_rule_counts": dict(
            sorted(
                Counter(
                    rule
                    for row in rows
                    for group in row["proof_required_groups"]
                    for rule in group["structural_eligibility"]["rules"]
                ).items()
            )
        ),
        "validation_status_counts": dict(sorted(Counter(row["validation_status"] for row in rows).items())),
        "by_trigger_stage": {
            stage: {
                "rows": len(stage_rows),
                "status_counts": dict(sorted(Counter(row["validation_status"] for row in stage_rows).items())),
            }
            for stage in sorted({row["trigger_stage"] for row in rows})
            if (stage_rows := [row for row in rows if row["trigger_stage"] == stage])
        },
        "secondary_review_rows": len(secondary),
        "secondary_review_cves": [row["cve_id"] for row in secondary],
        "production_default_changed": False,
        "human_signed_rows": 0,
        "cautions": [
            "The 56 rows are the complete impact set of a post-hoc normalization profile, not a representative sample.",
            "Live HTTP availability and dynamic page content can change after the source snapshots.",
            "Structural and network corroboration are not real-human validation.",
            "Text similarity is an uncalibrated baseline diagnostic and never establishes network corroboration.",
            "A superseded pilot seal and outputs are retained for audit but excluded from all merged results.",
        ],
    }

    for name, path in paths.items():
        if name in {"agent_e", "agent_f"}:
            continue
        if sha256(path) != input_hashes[name]:
            raise ValueError(f"sealed input changed during build: {path}")
    if sha256(builder_path) != builder_hash:
        raise ValueError("builder code changed during build")
    if paths["agent_e"].exists() or paths["agent_f"].exists():
        raise ValueError("reference identity reviewer output appeared during sealing")
    output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(row_path, rows)
    write_jsonl(probe_path, [probes[url] for url in urls])
    write_jsonl(masked_path, [masked_secondary_row(row) for row in secondary])
    atomic_write_text(
        summary_path,
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
    )
    atomic_write_text(markdown_path, render_markdown(summary))
    sealed_at_ns = time.time_ns()
    manifest = {
        "artifact_type": "reference_normalization_impact_manifest",
        "review_protocol_revision": 2,
        "sealed_at_ns": sealed_at_ns,
        "reviewer_outputs_absent_at_seal": True,
        "source_inputs_unchanged_during_build": True,
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "inputs": {
            name: {"path": str(path), "sha256": input_hashes[name]}
            for name, path in paths.items()
            if name not in {"agent_e", "agent_f"}
        },
        "outputs": {
            name: {"path": str(path), "sha256": sha256(path)}
            for name, path in {
                "validation_rows": row_path,
                "probe_records": probe_path,
                "secondary_worklist": masked_path,
                "summary": summary_path,
                "markdown": markdown_path,
            }.items()
        },
        "reviewer_outputs": {
            "agent_e": str(paths["agent_e"]),
            "agent_f": str(paths["agent_f"]),
        },
        "code": {
            "builder": {
                "path": str(builder_path),
                "sha256": builder_hash,
            },
            "merge": {
                "path": str(paths["merge_code"]),
                "sha256": sha256(paths["merge_code"]),
            },
        },
        "run_configuration": {
            "timeout_seconds": args.timeout_seconds,
            "refresh": args.refresh,
            "max_bytes": DEFAULT_MAX_BYTES,
            "max_text_chars": DEFAULT_MAX_TEXT_CHARS,
            "cache_max_age_seconds": DEFAULT_CACHE_MAX_AGE_SECONDS,
            "probe_schema_version": PROBE_SCHEMA_VERSION,
            "probe_attempts": 3,
        },
        "runtime": {
            "python": sys.version,
            "platform": platform.platform(),
            "openssl": ssl.OPENSSL_VERSION,
        },
    }
    atomic_write_text(
        manifest_path,
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
    )
    print(f"Wrote {row_path}")
    print(f"Wrote {probe_path}")
    print(f"Wrote {masked_path}")
    print(f"Wrote {summary_path}")
    print(f"Wrote {manifest_path}")
    print(json.dumps(summary["validation_status_counts"], sort_keys=True))
    return 0


def main() -> int:
    args = parse_args()
    output_dir = resolve(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    lock_path = output_dir / ".reference_impact_build.lock"
    try:
        descriptor = os.open(
            lock_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
    except FileExistsError as exc:
        raise ValueError(f"reference impact build lock exists: {lock_path}") from exc
    try:
        os.write(descriptor, f"pid={os.getpid()}\n".encode())
        os.close(descriptor)
        return build(args)
    finally:
        lock_path.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
