#!/usr/bin/env python3

from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

import merge_rq2_typing_holdout_reviews as target


def blind() -> dict:
    return {
        "sample_id": "rq2_typing_holdout_v1:001",
        "cve_id": "CVE-2026-0001",
        "field": "severity",
        "reference_context": {
            "nvd_urls": ["https://example.test/nvd"],
            "ghsa_urls": ["https://example.test/ghsa"],
        },
    }


def review() -> dict:
    annotation = {
        "sample_id": "rq2_typing_holdout_v1:001",
        "cve_id": "CVE-2026-0001",
        "field": "severity",
        "discrepancy_label": "factual_conflict",
        "adjudicated_source": "abstain",
        "adjudicated_value": "",
        "evidence_urls": [],
        "rationale": "The canonical severity values make materially incompatible field claims.",
        "evidence_notes": "No source selection is performed for RQ2 typing.",
        "uncertainty_notes": "",
        "version_reasoning_type": "not_applicable",
        "confidence": "high",
        "needs_human_review": False,
    }
    return {
        "schema_version": "expert_candidate_v1",
        "candidate_status": "unreviewed",
        "label_is_human": False,
        "annotator_type": "ai_security_expert",
        "annotator_id": "codex_security_expert:gpt-5.5:reviewer_a",
        "model": "gpt-5.5",
        "api_route": "codex_cli",
        "execution_backend": "codex-cli",
        "execution_backend_version": "codex-cli 0.144.4",
        "execution_backend_sha256": "codex-cli-hash",
        "execution_reasoning_effort": "high",
        "execution_max_output_tokens": None,
        "execution_session_id": "019f-test-session",
        "execution_usage": {"input_tokens": 100, "output_tokens": 20},
        "schedule": "input",
        "rq2_contract_mode": "strict",
        "pass_id": "reviewer_a",
        "generated_at": "2026-07-15T12:00:00+00:00",
        "prompt_path": "/tmp/prompt.md",
        "prompt_sha256": "prompt-hash",
        "input_path": "/tmp/blind.jsonl",
        "input_sha256": "input-hash",
        "binding_manifest_path": "/tmp/manifest.json",
        "binding_manifest_sha256": "manifest-hash",
        "sample_id": "rq2_typing_holdout_v1:001",
        "original_sample_id": None,
        "baseline_status": None,
        "contract_normalizations": [],
        "annotation": annotation,
    }


class MergeRq2TypingHoldoutReviewsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.blind_path = root / "blind.jsonl"
        self.prompt_path = root / "prompt.md"
        self.manifest_path = root / "manifest.json"
        self.blind_path.write_text("{}\n", encoding="utf-8")
        self.prompt_path.write_text("prompt\n", encoding="utf-8")
        self.manifest_path.write_text("{}\n", encoding="utf-8")
        self.execution = {
            "backend": "codex-cli",
            "api_route": "codex_cli",
            "model": "gpt-5.5",
            "version": "codex-cli 0.144.4",
            "sha256": "codex-cli-hash",
            "reasoning_effort": "high",
            "max_output_tokens": None,
        }

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def bound_review(self) -> dict:
        value = review()
        value["input_path"] = str(self.blind_path)
        value["input_sha256"] = target.sha256(self.blind_path)
        value["prompt_path"] = str(self.prompt_path)
        value["prompt_sha256"] = target.sha256(self.prompt_path)
        value["binding_manifest_path"] = str(self.manifest_path)
        value["binding_manifest_sha256"] = target.sha256(self.manifest_path)
        return value

    def test_valid_strict_review_passes(self) -> None:
        annotation = target.validate_review(
            self.bound_review(),
            blind(),
            expected_pass_id="reviewer_a",
            expected_input_path=self.blind_path,
            expected_prompt_path=self.prompt_path,
            expected_manifest_path=self.manifest_path,
            expected_manifest_sha256=target.sha256(self.manifest_path),
            expected_execution=self.execution,
        )
        self.assertTrue(target.is_strict_consensus(annotation, annotation))

    def test_baseline_leak_is_rejected(self) -> None:
        value = self.bound_review()
        value["baseline_status"] = "factual_conflict"
        with self.assertRaisesRegex(ValueError, "leaked baseline_status"):
            target.validate_review(
                value,
                blind(),
                expected_pass_id="reviewer_a",
                expected_input_path=self.blind_path,
                expected_prompt_path=self.prompt_path,
                expected_manifest_path=self.manifest_path,
                expected_manifest_sha256=target.sha256(self.manifest_path),
                expected_execution=self.execution,
            )

    def test_codex_binary_hash_mismatch_is_rejected(self) -> None:
        value = self.bound_review()
        value["execution_backend_sha256"] = "different"
        with self.assertRaisesRegex(ValueError, "backend hash mismatch"):
            target.validate_review(
                value,
                blind(),
                expected_pass_id="reviewer_a",
                expected_input_path=self.blind_path,
                expected_prompt_path=self.prompt_path,
                expected_manifest_path=self.manifest_path,
                expected_manifest_sha256=target.sha256(self.manifest_path),
                expected_execution=self.execution,
            )

    def test_output_token_cap_mismatch_is_rejected(self) -> None:
        value = self.bound_review()
        value["execution_max_output_tokens"] = 512
        with self.assertRaisesRegex(ValueError, "output-token cap mismatch"):
            target.validate_review(
                value,
                blind(),
                expected_pass_id="reviewer_a",
                expected_input_path=self.blind_path,
                expected_prompt_path=self.prompt_path,
                expected_manifest_path=self.manifest_path,
                expected_manifest_sha256=target.sha256(self.manifest_path),
                expected_execution=self.execution,
            )

    def test_review_request_excludes_exact_label_from_strict_consensus(self) -> None:
        left = review()["annotation"]
        right = copy.deepcopy(left)
        right["needs_human_review"] = True
        self.assertFalse(target.is_strict_consensus(left, right))

    def test_uncertain_exact_agreement_is_not_strict(self) -> None:
        left = review()["annotation"]
        left["discrepancy_label"] = "uncertain"
        left["needs_human_review"] = True
        self.assertFalse(target.is_strict_consensus(left, left))


if __name__ == "__main__":
    unittest.main()
