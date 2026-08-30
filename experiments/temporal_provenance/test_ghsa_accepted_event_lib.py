import json
import unittest
from collections import Counter

import ghsa_accepted_event_lib as target


def affected_record(*, fixed: str = "2.0.0", events=None, aliases=None):
    return {
        "id": "GHSA-2345-6789-cfgh",
        "aliases": aliases or ["CVE-2024-0001"],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "demo"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": events
                        or [{"introduced": "0"}, {"fixed": fixed}],
                    }
                ],
                "versions": ["1.1", "1.0"],
            }
        ],
    }


class AtomTests(unittest.TestCase):
    def test_affected_versions_are_order_insensitive(self):
        left = affected_record()
        right = affected_record()
        right["affected"][0]["versions"] = ["1.0", "1.1"]
        self.assertEqual(target.affected_atoms(left), target.affected_atoms(right))

    def test_range_event_order_is_preserved(self):
        left = affected_record(events=[{"introduced": "0"}, {"fixed": "2.0.0"}])
        right = affected_record(events=[{"fixed": "2.0.0"}, {"introduced": "0"}])
        self.assertNotEqual(target.affected_atoms(left), target.affected_atoms(right))

    def test_duplicate_package_identity_fails_closed(self):
        record = affected_record()
        record["affected"].append(json.loads(json.dumps(record["affected"][0])))
        with self.assertRaises(target.AmbiguousProviderObject):
            target.affected_atoms(record)

    def test_fix_reference_atoms_exclude_generic_pages(self):
        record = {
            "references": [
                {"type": "WEB", "url": "https://github.com/acme/demo/commit/abcdef1"},
                {"type": "WEB", "url": "https://example.com/advisory"},
            ]
        }
        atoms = target.reference_atoms(record)
        self.assertEqual(sum(atoms.values()), 1)
        self.assertIn("git_commit", next(iter(atoms)))


class DeltaTests(unittest.TestCase):
    def test_exact_compares_delta_not_final_projection(self):
        old_atom = "old"
        new_atom = "new"
        proposal = target.multiset_delta(
            Counter({old_atom: 1, "proposal-only-context": 1}),
            Counter({new_atom: 1, "proposal-only-context": 1}),
        )
        main = target.multiset_delta(
            Counter({old_atom: 1, "main-only-context": 1}),
            Counter({new_atom: 1, "main-only-context": 1}),
        )
        relation = target.classify_delta_relation(
            proposal,
            main,
            Counter({new_atom: 1, "proposal-only-context": 1}),
            Counter({old_atom: 1, "main-only-context": 1}),
        )
        self.assertEqual(relation, "exact")

    def test_partial_requires_direction_preserving_overlap(self):
        proposal = target.FieldDelta(Counter({"a": 1, "b": 1}), Counter())
        main = target.FieldDelta(Counter({"a": 1, "extra": 1}), Counter())
        self.assertEqual(
            target.classify_delta_relation(
                proposal, main, Counter({"a": 1, "b": 1}), Counter()
            ),
            "partial",
        )

        conflict = target.FieldDelta(Counter({"a": 1}), Counter({"b": 1}))
        self.assertEqual(
            target.classify_delta_relation(
                proposal, conflict, Counter({"a": 1, "b": 1}), Counter()
            ),
            "same_field_nonmatching_or_unlinked",
        )

    def test_already_present_precedes_no_field_delta(self):
        proposal = target.FieldDelta(Counter({"new": 1}), Counter({"old": 1}))
        relation = target.classify_delta_relation(
            proposal,
            target.FieldDelta(Counter(), Counter()),
            Counter({"new": 1}),
            Counter({"new": 1}),
        )
        self.assertEqual(relation, "already_present_before_disposition")


class StabilityTests(unittest.TestCase):
    def test_scans_all_states_and_catches_late_reversion(self):
        delta = target.FieldDelta(Counter({"new": 1}), Counter({"old": 1}))
        result = target.verify_delta_stability(
            Counter({"new": 1}),
            delta,
            [Counter({"new": 1}), Counter({"new": 1}), Counter({"old": 1})],
        )
        self.assertEqual(result["status"], "reverted_or_overwritten")
        self.assertEqual(result["failures"][0]["state_position"], 2)

    def test_stable_delta_allows_unrelated_atoms(self):
        delta = target.FieldDelta(Counter({"new": 1}), Counter({"old": 1}))
        result = target.verify_delta_stability(
            Counter({"new": 1}),
            delta,
            [Counter({"new": 1, "unrelated": 1})],
        )
        self.assertEqual(result["status"], "stable")


class IdentityTests(unittest.TestCase):
    def test_multi_cve_advisory_is_not_duplicated(self):
        record = affected_record(aliases=["CVE-2024-0001", "CVE-2024-0002"])
        self.assertIsNone(target.unique_cve_alias(record))

    def test_ghsa_id_is_read_across_path_families(self):
        path = (
            "advisories/github-reviewed/2024/01/"
            "GHSA-2345-6789-cfgh/GHSA-2345-6789-cfgh.json"
        )
        self.assertEqual(target.ghsa_id_from_path(path), "GHSA-2345-6789-cfgh")


if __name__ == "__main__":
    unittest.main()
