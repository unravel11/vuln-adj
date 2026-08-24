import unittest

import analyze_rq2_residual_nonaffected_evidence as target


class AnalyzeResidualNonAffectedEvidenceTests(unittest.TestCase):
    def test_lightning_gate_detects_direct_unhandled_state_access(self):
        source = '''
class Service:
    def post(self, path):
        return lambda fn: fn
fastapi_service = Service()

@fastapi_service.post("/api/v1/state")
async def post_state(request):
    body = await request.json()
    if "stage" in body:
        return body["stage"]
    return body["state"]
'''
        self.assertTrue(target.lightning_source_gate(source)["passed"])

    def test_lightning_gate_rejects_local_try(self):
        source = '''
class Service:
    def post(self, path):
        return lambda fn: fn
fastapi_service = Service()

@fastapi_service.post("/api/v1/state")
async def post_state(request):
    body = await request.json()
    try:
        return body["state"]
    except KeyError:
        return None
'''
        self.assertFalse(target.lightning_source_gate(source)["passed"])

    def test_froxlor_patch_gate_requires_validation_without_auth_markers(self):
        patch = "\n".join(
            [
                "+if (empty(trim($name))) {",
                "+  Response::standardError('stringisempty');",
                "+}",
                "+if (empty(trim($email))) {",
                "+  Response::standardError('stringisempty');",
                "+}",
            ]
        )
        gate = target.froxlor_patch_gate(patch)
        self.assertTrue(gate["passed_as_insufficient_for_access_control"])

    def test_cwe_page_gate_uses_visible_text_across_tags(self):
        html = "<h1>CWE CATEGORY: Business Logic Errors</h1><p>Vulnerability Mapping <span>:</span> <b>PROHIBITED</b></p>"
        self.assertTrue(
            target.cwe_page_gate(
                html,
                "CWE CATEGORY: Business Logic Errors",
                "Vulnerability Mapping: PROHIBITED",
            )
        )

    def test_repair_collapses_only_fixed_suse_suffix(self):
        single = "https://bugzilla.suse.com/show_bug.cgi?id=CVE-2023-32187https:/"
        double = "https://bugzilla.suse.com/show_bug.cgi?id=CVE-2023-32187https://"
        expected = "https://bugzilla.suse.com/show_bug.cgi?id=CVE-2023-32187"
        self.assertEqual(target.repair_suse_bug_lookup(single), expected)
        self.assertEqual(target.repair_suse_bug_lookup(double), expected)
        self.assertEqual(target.repair_suse_bug_lookup(expected), expected)

    def test_reference_relation_profiles(self):
        common = "https://github.com/advisory"
        nvd = {common, "bad-a"}
        ghsa = {common, "bad-b", "repo"}
        self.assertEqual(target.reference_relation(nvd, ghsa), "overlap_non_subset")
        self.assertEqual(
            target.reference_relation({common, "bad"}, {common, "bad", "repo"}),
            "nvd_subset_of_ghsa",
        )

    def test_reference_relation_labels(self):
        self.assertEqual(
            target.label_for_reference_relation("overlap_non_subset"),
            "representation_discrepancy",
        )
        self.assertEqual(
            target.label_for_reference_relation("nvd_subset_of_ghsa"),
            "incomplete",
        )


if __name__ == "__main__":
    unittest.main()
