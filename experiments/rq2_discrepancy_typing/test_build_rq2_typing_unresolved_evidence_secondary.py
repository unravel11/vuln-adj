import unittest

import build_rq2_typing_unresolved_evidence_secondary as subject


def annotation(label="uncertain", confidence="medium", review=True):
    return {
        "discrepancy_label": label,
        "confidence": confidence,
        "needs_human_review": review,
    }


class BuildUnresolvedEvidenceSecondaryTests(unittest.TestCase):
    def test_vote_groups_cover_fixed_failure_modes(self):
        zero = {"reviewer_a": annotation(), "reviewer_b": annotation(), "reviewer_c": annotation()}
        one = {**zero, "reviewer_a": annotation("incomplete", "medium", False)}
        two = {
            "reviewer_a": annotation("incomplete", "medium", False),
            "reviewer_b": annotation("factual_conflict", "medium", False),
            "reviewer_c": annotation(),
        }
        three = {
            "reviewer_a": annotation("incomplete", "medium", False),
            "reviewer_b": annotation("factual_conflict", "medium", False),
            "reviewer_c": annotation("representation_discrepancy", "medium", False),
        }
        self.assertEqual(subject.vote_group(zero), "zero_qualified")
        self.assertEqual(subject.vote_group(one), "one_qualified")
        self.assertEqual(subject.vote_group(two), "two_qualified_split")
        self.assertEqual(subject.vote_group(three), "three_qualified_split")

    def test_github_fetch_transformations_are_deterministic(self):
        self.assertEqual(
            subject.derive_fetch_url("https://github.com/o/r/commit/abc"),
            "https://github.com/o/r/commit/abc.patch",
        )
        self.assertEqual(
            subject.derive_fetch_url("https://github.com/o/r/blob/main/a.txt"),
            "https://raw.githubusercontent.com/o/r/main/a.txt",
        )

    def test_specific_evidence_ranks_before_repository_and_nvd(self):
        advisory = "https://github.com/o/r/security/advisories/GHSA-a-b-c"
        repo = "https://github.com/o/r"
        nvd = "https://nvd.nist.gov/vuln/detail/CVE-2024-1"
        self.assertLess(subject.reference_rank(advisory), subject.reference_rank(repo))
        self.assertLess(subject.reference_rank(repo), subject.reference_rank(nvd))

    def test_select_urls_caps_and_omits_low_priority_when_specific_exists(self):
        urls = [f"https://vendor.example/security/advisory-{index}" for index in range(8)]
        row = {
            "reference_context": {
                "nvd_urls": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1"],
                "ghsa_urls": urls,
            }
        }
        selected = subject.select_urls(row)
        self.assertEqual(len(selected), 6)
        self.assertNotIn("https://nvd.nist.gov/vuln/detail/CVE-2024-1", selected)


if __name__ == "__main__":
    unittest.main()
