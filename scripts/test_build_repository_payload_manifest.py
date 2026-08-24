#!/usr/bin/env python3

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from build_repository_payload_manifest import (
    build_rows,
    verify_manifest,
    write_manifest,
)


class RepositoryPayloadManifestTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name)
        subprocess.run(["git", "init", "-q"], cwd=self.repo, check=True)
        (self.repo / ".gitignore").write_text("payload/\n", encoding="utf-8")
        payload = self.repo / "payload"
        payload.mkdir()
        (payload / "data.bin").write_bytes(b"payload bytes\n")
        (payload / "manifest.json").write_text("{}\n", encoding="utf-8")
        subprocess.run(
            ["git", "add", "-f", "payload/manifest.json"],
            cwd=self.repo,
            check=True,
        )
        self.output = self.repo / "inventory.tsv"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_tracked_control_file_is_not_in_payload_inventory(self) -> None:
        rows = build_rows(self.repo, ("payload",))
        self.assertEqual([row[2] for row in rows], ["payload/data.bin"])
        write_manifest(self.output, rows, ("payload",))
        verify_manifest(self.repo, self.output, ("payload",))

    def test_verify_detects_byte_change(self) -> None:
        rows = build_rows(self.repo, ("payload",))
        write_manifest(self.output, rows, ("payload",))
        (self.repo / "payload/data.bin").write_bytes(b"changed\n")
        with self.assertRaisesRegex(RuntimeError, "size mismatch|sha256 mismatch"):
            verify_manifest(self.repo, self.output, ("payload",))


if __name__ == "__main__":
    unittest.main()
