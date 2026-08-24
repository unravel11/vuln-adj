#!/usr/bin/env python3
"""Focused tests for RQ2 reference-normalization variants."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))

from analyze_reference_normalization_variants import (  # noqa: E402
    VARIANTS,
    canonicalize_reference_url,
    classify_references,
)


def main() -> int:
    current = VARIANTS["current_exact"]
    transport = VARIANTS["transport_and_line"]
    known_query = VARIANTS["transport_line_known_query"]
    aliases = VARIANTS["transport_line_known_query_aliases"]

    http_pr = "http://github.com/example/project/pull/1"
    https_pr = "https://github.com/example/project/pull/1"
    assert canonicalize_reference_url(http_pr, current) != canonicalize_reference_url(
        https_pr, current
    )
    assert canonicalize_reference_url(http_pr, transport) == canonicalize_reference_url(
        https_pr, transport
    )

    encoded_line = "https://github.com/o/r/blob/main/a.py%23L10-L12"
    plain_file = "https://github.com/o/r/blob/main/a.py"
    assert canonicalize_reference_url(encoded_line, transport) == plain_file

    dynamic = "https://vendor.example/advisory/CVE-1?view=full"
    base = "https://vendor.example/advisory/CVE-1"
    assert canonicalize_reference_url(dynamic, transport) != base
    assert canonicalize_reference_url(dynamic, known_query) != base

    liferay_dynamic = (
        "https://liferay.dev/portal/security/known-vulnerabilities/-/"
        "asset_publisher/jekt/content/cve-2023-35029?p_r_p_assetEntryId=1"
    )
    liferay_base = (
        "https://liferay.dev/portal/security/known-vulnerabilities/-/"
        "asset_publisher/jekt/content/cve-2023-35029"
    )
    assert canonicalize_reference_url(liferay_dynamic, known_query) == liferay_base

    global_ghsa = "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"
    repository_ghsa = (
        "https://github.com/org/repo/security/advisories/GHSA-aaaa-bbbb-cccc"
    )
    assert canonicalize_reference_url(global_ghsa, aliases) == canonicalize_reference_url(
        repository_ghsa, aliases
    )

    huntr_com = "https://huntr.com/bounties/11111111-2222-3333-4444-555555555555"
    huntr_dev = "https://huntr.dev/bounties/11111111-2222-3333-4444-555555555555"
    assert canonicalize_reference_url(huntr_com, aliases) == canonicalize_reference_url(
        huntr_dev, aliases
    )

    assert classify_references([https_pr], [https_pr, base], current) == "incomplete"
    assert (
        classify_references([https_pr, base], [https_pr, global_ghsa], current)
        == "representation_discrepancy"
    )
    assert (
        classify_references(
            [global_ghsa], [repository_ghsa, "https://nvd.nist.gov/vuln/CVE-1"], aliases
        )
        == "incomplete"
    )

    core_path = Path(__file__).resolve().parents[2] / "scripts/build_field_discrepancies.py"
    spec = importlib.util.spec_from_file_location("build_field_discrepancies", core_path)
    assert spec and spec.loader
    core = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(core)
    parity_urls = [
        http_pr,
        https_pr,
        encoded_line,
        dynamic,
        liferay_dynamic,
        global_ghsa,
        repository_ghsa,
        huntr_com,
        huntr_dev,
    ]
    for url in parity_urls:
        assert canonicalize_reference_url(url, current) == core.canonicalize_url(
            url, profile="current"
        )
        assert canonicalize_reference_url(url, aliases) == core.canonicalize_url(
            url, profile="resource_identity_v1"
        )
    assert (
        core.canonicalize_url("github.com/org/repo", profile="current")
        == "https:///github.com/org/repo"
    )
    print("reference normalization focused tests: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
