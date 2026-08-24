#!/usr/bin/env python3

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import run_expert_candidate_annotation as target


def model_input(field: str = "published") -> dict:
    return {
        "task_kind": "rq2",
        "sample_id": "rq2_holdout:001",
        "cve_id": "CVE-2026-0001",
        "field": field,
        "nvd_value": "2026-01-01T00:00:00Z",
        "ghsa_value": "2026-01-02T00:00:00Z",
        "reference_context": {
            "nvd_urls": ["https://example.test/nvd"],
            "ghsa_urls": ["https://example.test/ghsa"],
        },
    }


def annotation(label: str = "representation_discrepancy") -> dict:
    return {
        "sample_id": "rq2_holdout:001",
        "cve_id": "CVE-2026-0001",
        "field": "published",
        "discrepancy_label": label,
        "adjudicated_source": "abstain",
        "adjudicated_value": "",
        "evidence_urls": [],
        "rationale": "The supplied values were compared under the explicit typing contract.",
        "evidence_notes": "No external source adjudication is performed in RQ2 mode.",
        "uncertainty_notes": "",
        "version_reasoning_type": "not_applicable",
        "confidence": "medium",
        "needs_human_review": False,
    }


class StrictRq2ContractTests(unittest.TestCase):
    def test_structured_schema_exposes_strict_rationale_constraint(self) -> None:
        properties = target.ANNOTATION_SCHEMA["properties"]
        self.assertEqual(properties["rationale"]["minLength"], 40)
        self.assertNotIn("uniqueItems", properties["evidence_urls"])

    def test_codex_cli_event_parser_binds_session_and_usage(self) -> None:
        metadata = target.parse_codex_cli_events(
            "\n".join(
                [
                    json.dumps(
                        {"type": "thread.started", "thread_id": "019f-test"}
                    ),
                    json.dumps(
                        {
                            "type": "turn.completed",
                            "usage": {"input_tokens": 100, "output_tokens": 20},
                        }
                    ),
                ]
            )
        )
        self.assertEqual(metadata["session_id"], "019f-test")
        self.assertEqual(metadata["usage"]["output_tokens"], 20)

    def test_openai_metadata_normalizes_chat_usage(self) -> None:
        usage = Namespace(
            model_dump=lambda: {"prompt_tokens": 120, "completion_tokens": 30}
        )
        metadata = target.openai_response_metadata(
            Namespace(id="chatcmpl-test", usage=usage)
        )
        self.assertEqual(metadata["session_id"], "chatcmpl-test")
        self.assertEqual(
            metadata["usage"], {"input_tokens": 120, "output_tokens": 30}
        )

    def test_execution_binding_rejects_unsealed_binary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "review_protocol": {
                            "execution_contract": {
                                "backend": "codex-cli",
                                "api_route": "codex_cli",
                                "version": "codex-cli 0.144.4",
                                "sha256": "sealed-hash",
                                "model": "gpt-5.5",
                                "reasoning_effort": "high",
                                "max_output_tokens": None,
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            args = Namespace(
                execution_backend_version="codex-cli 0.144.4",
                execution_backend_sha256="different-hash",
                backend="codex-cli",
                model="gpt-5.5",
                codex_reasoning_effort="high",
                max_output_tokens=None,
                use_fallback=False,
            )
            with self.assertRaisesRegex(ValueError, "differs from seal"):
                target.verify_execution_binding(args, manifest_path)

    def test_execution_binding_rejects_unsealed_output_token_cap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "review_protocol": {
                            "execution_contract": {
                                "backend": "openai",
                                "api_route": "primary",
                                "version": "openai-python 2.41.0",
                                "sha256": None,
                                "model": "gpt-5.5",
                                "reasoning_effort": None,
                                "max_output_tokens": 512,
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            args = Namespace(
                execution_backend_version="openai-python 2.41.0",
                execution_backend_sha256=None,
                backend="openai",
                model="gpt-5.5",
                codex_reasoning_effort="high",
                max_output_tokens=256,
                use_fallback=False,
            )
            with self.assertRaisesRegex(ValueError, "max_output_tokens"):
                target.verify_execution_binding(args, manifest_path)

    def test_rq2_model_input_includes_frozen_evidence_without_expanding_urls(self) -> None:
        row = model_input("affected_versions")
        row["evidence_context"] = {
            "records": [
                {
                    "url": "https://example.test/ghsa",
                    "host": "example.test",
                    "title": "Frozen advisory",
                    "published": "2026-01-01",
                    "fetch_status": "ok",
                    "fetch_detail": "HTTP 200",
                    "text_snippet": "The package and fixed version are explicit.",
                }
            ]
        }
        built = target.build_model_input(
            row,
            task_kind="rq2",
            max_evidence_records=8,
            max_evidence_chars=3200,
        )
        self.assertEqual(built["evidence_context"]["records_supplied"], 1)
        self.assertEqual(
            built["allowed_evidence_urls"],
            ["https://example.test/ghsa", "https://example.test/nvd"],
        )

    def test_strict_mode_does_not_rewrite_published_label(self) -> None:
        parsed = {"annotations": [annotation()]}
        rows = target.validate_batch([model_input()], parsed, "strict")
        self.assertEqual(rows[0]["discrepancy_label"], "representation_discrepancy")
        self.assertEqual(rows[0]["_contract_normalizations"], [])

    def test_legacy_mode_preserves_historical_publication_normalization(self) -> None:
        parsed = {"annotations": [annotation()]}
        rows = target.validate_batch([model_input()], parsed, "legacy")
        self.assertEqual(rows[0]["discrepancy_label"], "temporal_discrepancy")
        self.assertIn(
            "published_different_calendar_dates_to_temporal_discrepancy",
            rows[0]["_contract_normalizations"],
        )

    def test_strict_mode_rejects_untraceable_evidence_url(self) -> None:
        value = annotation()
        value["evidence_urls"] = ["https://example.test/not-supplied"]
        with self.assertRaisesRegex(ValueError, "absent from the blind input"):
            target.validate_batch([model_input()], {"annotations": [value]}, "strict")

    def test_strict_mode_rejects_hidden_source_normalization(self) -> None:
        value = copy.deepcopy(annotation())
        value["adjudicated_source"] = "nvd"
        with self.assertRaisesRegex(ValueError, "must abstain"):
            target.validate_batch([model_input()], {"annotations": [value]}, "strict")


if __name__ == "__main__":
    unittest.main()
