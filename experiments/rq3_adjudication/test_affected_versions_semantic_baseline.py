#!/usr/bin/env python3
"""Focused checks for the conservative affected-version semantic baseline."""

from __future__ import annotations

from affected_versions_semantic_baseline import (
    package_gated_token_prediction,
    package_profile,
    package_range_evidence_prediction,
    range_relation,
    repository_crosswalk_package_gated_token_prediction,
    repository_crosswalk_package_profile,
)
from evaluate_affected_versions_silver_v2 import (
    canonical_token_present,
    contextual_version_claim_matches,
)


def support(nvd: int = 0, ghsa: int = 0) -> dict[str, dict]:
    return {
        "nvd": {"score": nvd, "matched_urls": [], "matched_tokens": []},
        "ghsa": {"score": ghsa, "matched_urls": [], "matched_tokens": []},
    }


def row(
    nvd_spans: list[dict],
    ghsa_spans: list[dict],
    nvd_packages: list[str],
    ghsa_packages: list[str],
    nvd_references: list[str] | None = None,
    ghsa_references: list[str] | None = None,
) -> dict:
    return {
        "nvd_value": nvd_spans,
        "ghsa_value": ghsa_spans,
        "nvd_context": {
            "package_names": nvd_packages,
            "references": nvd_references or [],
        },
        "ghsa_context": {
            "package_names": ghsa_packages,
            "references": ghsa_references or [],
        },
    }


def main() -> int:
    assert canonical_token_present("Affected version 3.0.0.Final", "3.0.0")
    assert canonical_token_present("Fixed in v12.4", "12.4")
    assert not canonical_token_present("Fixed in 3.0.1", "3.0.0")
    assert not canonical_token_present("CVSS Version v4.0", "4.0.0")
    assert not canonical_token_present("CVSS Version v3.1", "3.1.0")

    assert contextual_version_claim_matches(
        "CVE-2023-0001 affects Demo 3.0.0.Final and is fixed in 3.1.0.Final.",
        "3.0.0",
        "CVE-2023-0001",
        canonical=True,
    )
    assert not contextual_version_claim_matches(
        "CVE-2023-0001 Change History Old Value: versions before 2.2.1 are vulnerable.",
        "2.2.1",
        "CVE-2023-0001",
        canonical=True,
    )
    assert not contextual_version_claim_matches(
        "CVE-2023-0001 Full Changelog: compare 2.6 with the fixed 3.0 release.",
        "2.6",
        "CVE-2023-0001",
        canonical=True,
    )
    assert not contextual_version_claim_matches(
        "CVE-2023-0001 release index includes 4.2.0.",
        "4.2.0",
        "CVE-2023-0001",
        canonical=False,
    )
    assert not contextual_version_claim_matches(
        "Demo 3.0.0 is affected.",
        "3.0.0",
        "CVE-2023-0001",
        canonical=False,
    )

    go_getter = row([], [], ["go-getter"], ["github.com/hashicorp/go-getter/v2"])
    assert package_profile(go_getter)["category"] == "leaf_package_overlap_only"

    mismatch = row([], [], ["imagemagick"], ["magick.net-q16-x64"])
    assert package_profile(mismatch)["category"] == "no_package_name_overlap"
    assert (
        package_gated_token_prediction(mismatch, support(nvd=2))["predicted_source"]
        == "abstain"
    )

    repository_bridge = row(
        [],
        [],
        ["apiman"],
        ["io.apiman:apiman-manager-api-rest-impl"],
        ["https://github.com/apiman/apiman/security/advisories/GHSA-demo"],
        ["https://github.com/apiman/apiman/releases/tag/3.1.0.Final"],
    )
    bridge_profile = repository_crosswalk_package_profile(repository_bridge)
    assert bridge_profile["category"] == "repository_crosswalk_overlap"
    assert bridge_profile["comparable"] is True
    assert (
        repository_crosswalk_package_gated_token_prediction(
            repository_bridge, support(nvd=1, ghsa=1)
        )["predicted_source"]
        == "both"
    )

    wrapper_conflict = row(
        [],
        [],
        ["imagemagick"],
        ["magick.net-q16-x64"],
        ["https://github.com/ImageMagick/ImageMagick/commit/demo"],
        [
            "https://github.com/ImageMagick/ImageMagick/commit/demo",
            "https://github.com/dlemstra/Magick.NET/releases/tag/demo",
        ],
    )
    wrapper_profile = repository_crosswalk_package_profile(wrapper_conflict)
    assert wrapper_profile["comparable"] is False
    assert (
        wrapper_profile["repository_crosswalk_profile"]["category"]
        == "conflicting_repository_bridge"
    )

    generic_poc = row(
        [],
        [],
        ["parse_javascript_sdk"],
        ["parse"],
        ["https://github.com/VulnSageAgent/PoCs/blob/main/demo.md"],
        ["https://github.com/VulnSageAgent/PoCs/blob/main/demo.md"],
    )
    generic_profile = repository_crosswalk_package_profile(generic_poc)
    assert generic_profile["comparable"] is False
    assert (
        generic_profile["repository_crosswalk_profile"]["category"]
        == "no_shared_repository"
    )

    vendor_prefix_only = row(
        [],
        [],
        ["snyk_cli"],
        ["snyk-php-plugin"],
        ["https://github.com/snyk/snyk-php-plugin/commit/demo"],
        ["https://github.com/snyk/snyk-php-plugin/commit/demo"],
    )
    assert repository_crosswalk_package_profile(vendor_prefix_only)["comparable"] is False

    boundary = row(
        [{"version_end_including": "1.2.3"}],
        [{"version_end_excluding": "1.2.4", "fixed": "1.2.4"}],
        ["demo"],
        ["demo"],
    )
    assert range_relation(boundary)["relation"] == "successor_boundary_candidate"
    assert (
        package_range_evidence_prediction(boundary, support())["predicted_source"]
        == "abstain"
    )
    assert (
        package_range_evidence_prediction(boundary, support(nvd=1))[
            "predicted_source"
        ]
        == "nvd"
    )
    assert (
        package_range_evidence_prediction(boundary, support(nvd=1, ghsa=1))[
            "predicted_source"
        ]
        == "both"
    )

    identical = row(
        [{"version_end_excluding": "1.2.4"}],
        [{"fixed": "1.2.4"}],
        ["demo"],
        ["demo"],
    )
    assert range_relation(identical)["relation"] == "normalized_interval_equivalent"
    assert (
        package_range_evidence_prediction(identical, support())["predicted_source"]
        == "both"
    )

    point_coverage = row(
        [{"version": "1.2.1"}, {"version": "1.2.2"}],
        [{"version_end_excluding": "1.2.3"}],
        ["demo"],
        ["demo"],
    )
    assert range_relation(point_coverage)["relation"] == "nvd_points_within_ghsa_ranges"
    assert (
        package_range_evidence_prediction(point_coverage, support())["predicted_source"]
        == "abstain"
    )

    comparable = row(
        [{"version_end_excluding": "2.0.0"}],
        [{"version_end_excluding": "1.9.0"}],
        ["tensorflow"],
        ["tensorflow", "tensorflow-cpu"],
    )
    assert (
        package_gated_token_prediction(comparable, support(ghsa=1))[
            "predicted_source"
        ]
        == "ghsa"
    )

    unparseable = row(
        [{"version_end_excluding": "release-next"}],
        [{"version_end_excluding": "release-fixed"}],
        ["demo"],
        ["demo"],
    )
    assert range_relation(unparseable)["relation"] == "unparseable_spans"
    print("affected_versions semantic baseline checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
