#!/usr/bin/env python3

from __future__ import annotations

import unittest

import build_field_discrepancies as target


class ReferenceNormalizationProfileTests(unittest.TestCase):
    def test_audited_profile_preserves_encoded_line_path(self) -> None:
        url = "http://github.com/org/repo/blob/rev/file.py%23L10-L20"
        original = target.canonicalize_url(url, profile="resource_identity_v1")
        audited = target.canonicalize_url(
            url, profile="resource_identity_audited_v1"
        )
        self.assertEqual(original, "https://github.com/org/repo/blob/rev/file.py")
        self.assertEqual(
            audited,
            "https://github.com/org/repo/blob/rev/file.py%23L10-L20",
        )

    def test_audited_profile_keeps_supported_resource_aliases(self) -> None:
        ghsa = target.canonicalize_url(
            "http://github.com/org/repo/security/advisories/GHSA-AAAA-BBBB-CCCC",
            profile="resource_identity_audited_v1",
        )
        huntr = target.canonicalize_url(
            "http://huntr.dev/bounties/12345678-abcd-1234-abcd-1234567890ab",
            profile="resource_identity_audited_v1",
        )
        self.assertEqual(ghsa, "github-advisory:ghsa-aaaa-bbbb-cccc")
        self.assertEqual(
            huntr,
            "huntr-bounty:12345678-abcd-1234-abcd-1234567890ab",
        )


if __name__ == "__main__":
    unittest.main()
