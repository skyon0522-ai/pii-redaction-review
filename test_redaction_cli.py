from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path


sys.path.insert(0, str(Path(__file__).absolute().parent))
import redaction_cli as cli  # noqa: E402


class LocalApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_artifact_root = cli.ARTIFACT_ROOT
        self.temp = tempfile.TemporaryDirectory(prefix="pii-review-test-", dir=cli.IMPROVED_DIR)
        self.root = Path(self.temp.name).absolute()
        self.assertTrue(self.root.is_relative_to(cli.IMPROVED_DIR.absolute()))
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        cli.ARTIFACT_ROOT = self.artifacts
        self.input = self.root / "synthetic.txt"
        self.input.write_text("é: qa.person@example.invalid", encoding="utf-8")
        self.proposal = self.artifacts / "proposal.json"
        self.approved = self.artifacts / "approved.json"

    def tearDown(self) -> None:
        cli.ARTIFACT_ROOT = self.original_artifact_root
        self.temp.cleanup()

    def make_proposal(self) -> tuple[str, dict]:
        path, digest, proposal = cli.create_proposal(self.input, self.proposal)
        self.assertEqual(path, self.proposal)
        self.assertFalse(self.approved.exists(), "proposal creation must not create an approved file")
        return digest, proposal

    def replace_proposal(self, proposal: dict) -> str:
        data = cli._json_bytes(proposal)
        self.proposal.write_bytes(data)
        return cli.sha256(data)

    def test_explicit_digest_creates_only_exclusive_local_approved_file(self) -> None:
        digest, proposal = self.make_proposal()
        self.assertEqual(len(proposal["findings"]), 1)
        finding = proposal["findings"][0]
        self.assertEqual(finding["entity_type"], "EMAIL_ADDRESS")
        self.assertEqual(finding["start"], 3)
        self.assertEqual(finding["utf8_start"], 4)
        self.assertEqual(proposal["masked_output"], "é: <EMAIL_ADDRESS>")
        self.assertNotIn("qa.person@example.invalid", proposal["masked_output"])

        self.input.write_text("changed input", encoding="utf-8")
        with self.assertRaisesRegex(cli.IntegrityError, "current input bytes differ"):
            cli.approve_proposal(self.input, self.proposal, digest, self.approved)
        self.input.write_text("é: qa.person@example.invalid", encoding="utf-8")
        with self.assertRaisesRegex(cli.IntegrityError, "digest is required"):
            cli.approve_proposal(self.input, self.proposal, None, self.approved)
        with self.assertRaisesRegex(cli.IntegrityError, "does not match"):
            cli.approve_proposal(self.input, self.proposal, "0" * 64, self.approved)
        self.assertFalse(self.approved.exists())

        path, _, approved = cli.approve_proposal(self.input, self.proposal, digest, self.approved)
        self.assertEqual(path, self.approved)
        self.assertEqual(approved["proposal_sha256"], digest)
        self.assertFalse(approved["approval_record"]["human_identity_authenticated"])
        self.assertFalse(approved["approval_record"]["cryptographic_signature"])
        self.assertFalse(approved["approval_record"]["external_handoff"])
        approved_bytes = self.approved.read_bytes()
        with self.assertRaisesRegex(cli.IntegrityError, "refusing to overwrite"):
            cli.approve_proposal(self.input, self.proposal, digest, self.approved)
        self.assertEqual(self.approved.read_bytes(), approved_bytes)

    def test_changed_proposal_output_fails_even_with_its_new_digest(self) -> None:
        digest, proposal = self.make_proposal()
        tampered = dict(proposal)
        tampered["masked_output"] = "altered reviewed output"
        tampered["masked_output_sha256"] = cli.sha256(tampered["masked_output"].encode("utf-8"))
        new_digest = self.replace_proposal(tampered)
        with self.assertRaisesRegex(cli.IntegrityError, "reviewed proposal SHA-256"):
            cli.approve_proposal(self.input, self.proposal, digest, self.approved)
        with self.assertRaisesRegex(cli.IntegrityError, "masked output differs"):
            cli.approve_proposal(self.input, self.proposal, new_digest, self.approved)
        self.assertFalse(self.approved.exists())

    def test_non_boundary_utf8_offset_fails_without_output(self) -> None:
        _, proposal = self.make_proposal()
        tampered = json.loads(json.dumps(proposal))
        tampered["findings"][0]["utf8_start"] = 1
        digest = self.replace_proposal(tampered)
        with self.assertRaisesRegex(cli.IntegrityError, "not a UTF-8 character boundary"):
            cli.approve_proposal(self.input, self.proposal, digest, self.approved)
        self.assertFalse(self.approved.exists())

    def test_stale_copied_source_fails_without_output(self) -> None:
        digest, _ = self.make_proposal()
        stale_root = self.root / "changed-copy"
        shutil.copytree(cli.COPY_ROOT, stale_root, ignore=shutil.ignore_patterns("__pycache__"))
        (stale_root / "LICENSE").write_bytes((stale_root / "LICENSE").read_bytes() + b"\nchanged")
        original_copy_root = cli.COPY_ROOT
        cli.COPY_ROOT = stale_root
        try:
            with self.assertRaisesRegex(cli.IntegrityError, "differs from pinned bytes"):
                cli.approve_proposal(self.input, self.proposal, digest, self.approved)
        finally:
            cli.COPY_ROOT = original_copy_root
        self.assertFalse(self.approved.exists())

    def test_non_email_synthetic_input_shows_email_only_false_negative(self) -> None:
        self.input.write_text("Synthetic person: Example Person; phone: 555-0101.", encoding="utf-8")
        _, proposal = self.make_proposal()
        self.assertEqual(proposal["findings"], [])
        self.assertEqual(proposal["masked_output"], "Synthetic person: Example Person; phone: 555-0101.")
        digest = cli.sha256(self.proposal.read_bytes())
        with self.assertRaisesRegex(cli.IntegrityError, "no findings were detected"):
            cli.approve_proposal(self.input, self.proposal, digest, self.approved)
        self.assertFalse(self.approved.exists())

    def test_cli_main_runs_two_separate_commands(self) -> None:
        stdout = StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(
                cli.main(["propose", "--input", str(self.input), "--proposal", str(self.proposal)]),
                0,
            )
        proposal_result = json.loads(stdout.getvalue())
        self.assertEqual(proposal_result["status"], "proposal_written")
        self.assertFalse(self.approved.exists())

        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(
                cli.main(
                    [
                        "approve",
                        "--input",
                        str(self.input),
                        "--proposal",
                        str(self.proposal),
                        "--reviewed-sha256",
                        proposal_result["proposal_sha256"],
                        "--approved",
                        str(self.approved),
                    ]
                ),
                0,
            )
        approved_result = json.loads(stdout.getvalue())
        self.assertEqual(approved_result["status"], "locally_approved")
        self.assertEqual(stderr.getvalue(), "")
        self.assertTrue(self.approved.is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
