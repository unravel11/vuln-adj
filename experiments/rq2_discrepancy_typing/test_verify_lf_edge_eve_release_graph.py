import unittest

import verify_lf_edge_eve_release_graph as target


class VerifyLfEdgeEveReleaseGraphTests(unittest.TestCase):
    def test_verifier_domain_is_independently_fixed(self):
        self.assertEqual(len(target.VERSIONS), 207)
        self.assertIn("9.4.3-lts", target.VERSIONS)

    def test_ref_parser_handles_annotated_tags(self):
        raw = (
            b"a" * 40 + b"\trefs/tags/9.4.3-lts\n"
            + b"b" * 40 + b"\trefs/tags/9.4.3-lts^{}\n"
        )
        parsed = target.parse_refs(raw)
        self.assertEqual(parsed["9.4.3-lts"]["ref_oid"], "a" * 40)
        self.assertEqual(parsed["9.4.3-lts"]["peeled_oid"], "b" * 40)

    def test_verifier_rejects_diverged_ancestry(self):
        self.assertTrue(target.ancestry_membership("ahead"))
        self.assertFalse(target.ancestry_membership("behind"))
        self.assertIsNone(target.ancestry_membership("diverged"))

    def test_verifier_patch_parser_is_component_specific(self):
        patch = b"diff --git a/pkg/xen-tools/a b/pkg/xen-tools/a\n"
        self.assertEqual(target.parse_patch_paths(patch), ["pkg/xen-tools/a"])

    def test_remote_manifest_path_relocates_to_local_project(self):
        remote = target.AUTHORITATIVE_PROJECT_ROOT / "AGENTS.md"
        self.assertEqual(target.resolve(remote), target.PROJECT_ROOT / "AGENTS.md")


if __name__ == "__main__":
    unittest.main()
