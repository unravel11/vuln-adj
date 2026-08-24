import json
import tempfile
import unittest
from pathlib import Path

import merge_rq2_post_profile_reviews as target


class MergePostProfileReviewsTests(unittest.TestCase):
    def test_request_log_audit_requires_complete_bound_success(self):
        execution = {
            "backend": "codex-cli",
            "version": "codex-cli 0.144.4",
            "sha256": "binary-hash",
            "model": "gpt-5.5",
        }
        request = {
            "event_type": "request",
            "pass_id": "reviewer_a",
            "input_sha256": "input-hash",
            "prompt_sha256": "prompt-hash",
            "binding_manifest_sha256": "manifest-hash",
            "execution_backend": "codex-cli",
            "execution_backend_version": "codex-cli 0.144.4",
            "execution_backend_sha256": "binary-hash",
            "model": "gpt-5.5",
            "schedule": "input",
            "items": [{"sample_id": "sample:001"}],
        }
        success = {
            "event_type": "response_success",
            "pass_id": "reviewer_a",
            "sample_ids": ["sample:001"],
            "execution_session_id": "session-a",
            "execution_usage": {"input_tokens": 10, "output_tokens": 4},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requests.jsonl"
            path.write_text(
                json.dumps(request) + "\n" + json.dumps(success) + "\n",
                encoding="utf-8",
            )
            result = target.audit_request_log(
                path,
                pass_id="reviewer_a",
                expected_samples={"sample:001"},
                execution=execution,
                input_hash="input-hash",
                prompt_hash="prompt-hash",
                manifest_hash="manifest-hash",
            )
        self.assertEqual(result["successful_rows"], 1)
        self.assertEqual(result["usage"]["input_tokens"], 10)
        self.assertEqual(result["session_ids"], {"session-a"})

    def test_request_log_audit_rejects_terminal_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requests.jsonl"
            path.write_text(
                json.dumps(
                    {
                        "event_type": "response_error",
                        "pass_id": "reviewer_a",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "error without matching request"):
                target.audit_request_log(
                    path,
                    pass_id="reviewer_a",
                    expected_samples=set(),
                    execution={},
                    input_hash="",
                    prompt_hash="",
                    manifest_hash="",
                )

    def test_request_log_audit_retains_unanswered_attempt_before_successful_retry(self):
        execution = {
            "backend": "codex-cli",
            "version": "codex-cli 0.144.4",
            "sha256": "binary-hash",
            "model": "gpt-5.5",
        }
        request = {
            "event_type": "request",
            "pass_id": "reviewer_b",
            "input_sha256": "input-hash",
            "prompt_sha256": "prompt-hash",
            "binding_manifest_sha256": "manifest-hash",
            "execution_backend": "codex-cli",
            "execution_backend_version": "codex-cli 0.144.4",
            "execution_backend_sha256": "binary-hash",
            "model": "gpt-5.5",
            "schedule": "input",
            "items": [{"sample_id": "sample:001"}],
        }
        success = {
            "event_type": "response_success",
            "pass_id": "reviewer_b",
            "sample_ids": ["sample:001"],
            "execution_session_id": "session-b",
            "execution_usage": {"input_tokens": 10, "output_tokens": 4},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requests.jsonl"
            path.write_text(
                json.dumps(request) + "\n" + json.dumps(request) + "\n" + json.dumps(success) + "\n",
                encoding="utf-8",
            )
            result = target.audit_request_log(
                path,
                pass_id="reviewer_b",
                expected_samples={"sample:001"},
                execution=execution,
                input_hash="input-hash",
                prompt_hash="prompt-hash",
                manifest_hash="manifest-hash",
            )
        self.assertEqual(result["successful_rows"], 1)
        self.assertEqual(result["failed_attempts"], 1)
        self.assertEqual(result["unanswered_validation_attempts"], 1)


if __name__ == "__main__":
    unittest.main()
