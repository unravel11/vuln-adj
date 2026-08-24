import io
import unittest
import zipfile

import verify_hutool_maven_release_graph as target


class VerifyHutoolMavenReleaseGraphTests(unittest.TestCase):
    def test_remote_manifest_path_relocates_to_local_project(self):
        remote = target.AUTHORITATIVE_PROJECT_ROOT / "AGENTS.md"
        self.assertEqual(target.resolve(remote), target.PROJECT_ROOT / "AGENTS.md")

    def test_verifier_catalog_binds_coordinate(self):
        body = (
            b"<metadata><groupId>cn.hutool</groupId><artifactId>hutool-core</artifactId>"
            b"<versioning><versions><version>5.8.21</version></versions></versioning></metadata>"
        )
        self.assertTrue(target.parse_catalog(body, "cn.hutool:hutool-core")["identity_bound"])
        self.assertFalse(target.parse_catalog(body, "cn.hutool:hutool-json")["identity_bound"])

    def test_verifier_jar_parser_requires_json_classes(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("cn/hutool/core/A.class", b"a")
        self.assertFalse(target.parse_jar(stream.getvalue(), "5.8.21")["bound"])

    def test_verifier_relation_is_directional(self):
        self.assertEqual(
            target.relation({"5.8.21"}, {"5.8.21", "5.8.22"}),
            "nvd_subset_of_ghsa",
        )
        self.assertEqual(target.candidate("nvd_subset_of_ghsa"), "incomplete")


if __name__ == "__main__":
    unittest.main()
