"""Private, local-only proposal and approval gate over the copied Presidio slice."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import re
import sys
import time
from pathlib import Path, PurePosixPath
from typing import Any


# Do not read or write bytecode caches left beside the copied source. The unique
# alternate cache path is intentionally never created; imports use checked .py.
sys.dont_write_bytecode = True
sys.pycache_prefix = str(
    Path(os.environ.get("TEMP", "."))
    / f"pii-redaction-review-{os.getpid()}-{time.time_ns()}"
)

IMPROVED_DIR = Path(__file__).absolute().parent
CANDIDATE_DIR = IMPROVED_DIR
COPY_ROOT = CANDIDATE_DIR / "copied-component"
MANIFEST_PATH = CANDIDATE_DIR / "SOURCE_MANIFEST.json"
ARTIFACT_ROOT = IMPROVED_DIR / "artifacts"
WORKFLOW_FILE = Path(__file__).absolute()

UPSTREAM_URL = "https://github.com/data-privacy-stack/presidio"
PINNED_COMMIT = "2523c7b74a469270c5c78bb253f140eafca21e31"
PINNED_MANIFEST_SHA256 = "4c9f79a0bf666eb3ad7d77ddb5f4127cbbe4a47227a34796419dac624c08bba9"
PROPOSAL_SCHEMA = "presidio-local-redaction-proposal/v1"
APPROVED_SCHEMA = "presidio-local-approved-redaction/v1"
PROPOSAL_SCOPE = "One pinned Presidio email pattern; local-only; input type is not verified; no external handoff."
PROPOSAL_FIELDS = {
    "schema",
    "source",
    "workflow_sha256",
    "imports",
    "input",
    "findings",
    "masked_output",
    "masked_output_sha256",
    "scope",
}


class IntegrityError(Exception):
    """A source, input, proposal, offset, or output integrity check failed."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise IntegrityError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _load_json(data: bytes, label: str) -> Any:
    try:
        return json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"{label} is not valid UTF-8 JSON: {exc}") from exc


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _read_regular_file(path: Path, label: str) -> bytes:
    if path.is_symlink():
        raise IntegrityError(f"{label} must not be a symlink: {path}")
    if not path.is_file():
        raise IntegrityError(f"{label} is missing or is not a regular file: {path}")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise IntegrityError(f"cannot read {label}: {exc}") from exc


def _read_utf8_input(path: str | Path) -> tuple[bytes, str]:
    input_path = Path(path)
    raw = _read_regular_file(input_path, "input")
    try:
        return raw, raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise IntegrityError(f"input is not valid UTF-8 at byte offset {exc.start}") from exc


def _manifest_and_source_digest() -> tuple[dict[str, Any], str]:
    manifest_bytes = _read_regular_file(MANIFEST_PATH, "source manifest")
    manifest_sha = sha256(manifest_bytes)
    if manifest_sha != PINNED_MANIFEST_SHA256:
        raise IntegrityError("source manifest digest differs from the accepted baseline")
    manifest = _load_json(manifest_bytes, "source manifest")
    if not isinstance(manifest, dict) or manifest.get("commit") != PINNED_COMMIT:
        raise IntegrityError("source manifest does not identify the pinned Presidio commit")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or len(entries) != 467:
        raise IntegrityError("source manifest entry count differs from the accepted baseline")
    if manifest.get("files") != 467 or manifest.get("git_blob_mismatches") != []:
        raise IntegrityError("source manifest summary differs from the accepted baseline")

    expected: dict[str, dict[str, Any]] = {}
    expected_dirs: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise IntegrityError("source manifest contains a malformed entry")
        relative = entry.get("path")
        if not isinstance(relative, str) or "\\" in relative:
            raise IntegrityError("source manifest contains an unsafe path")
        pure = PurePosixPath(relative)
        if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
            raise IntegrityError("source manifest contains an unsafe path")
        normalized = pure.as_posix()
        if normalized in expected:
            raise IntegrityError(f"source manifest repeats path: {normalized}")
        expected[normalized] = entry
        for parent in pure.parents:
            if str(parent) != ".":
                expected_dirs.add(parent.as_posix())

    if COPY_ROOT.is_symlink() or not COPY_ROOT.is_dir():
        raise IntegrityError("copied Presidio source root is missing or unsafe")

    actual_expected: set[str] = set()
    actual_digest_rows: list[dict[str, str]] = []
    for path in COPY_ROOT.rglob("*"):
        relative = path.relative_to(COPY_ROOT).as_posix()
        if path.is_symlink():
            raise IntegrityError(f"copied source contains a symlink: {relative}")
        if path.is_dir():
            in_cache = "__pycache__" in PurePosixPath(relative).parts
            if not in_cache and relative not in expected_dirs:
                raise IntegrityError(f"copied source contains an unexpected directory: {relative}")
            continue
        if not path.is_file():
            raise IntegrityError(f"copied source contains a non-regular entry: {relative}")
        if relative not in expected:
            parts = PurePosixPath(relative).parts
            if "__pycache__" in parts and path.suffix == ".pyc":
                # Pre-existing runtime caches are not source. Imports below are
                # redirected to a fresh empty cache prefix so these cannot run.
                continue
            raise IntegrityError(f"copied source contains an unexpected file: {relative}")
        actual_expected.add(relative)

    missing = set(expected) - actual_expected
    if missing:
        raise IntegrityError(f"copied source is missing a manifest file: {sorted(missing)[0]}")

    for relative in sorted(expected):
        entry = expected[relative]
        data = _read_regular_file(COPY_ROOT / Path(*PurePosixPath(relative).parts), relative)
        actual_sha = sha256(data)
        if len(data) != entry.get("bytes") or actual_sha != entry.get("sha256"):
            raise IntegrityError(f"copied source differs from pinned bytes: {relative}")
        git_blob = hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
        if git_blob != entry.get("git_blob") or git_blob != entry.get("copy_git_blob"):
            raise IntegrityError(f"copied source Git blob differs from pin: {relative}")
        actual_digest_rows.append({"path": relative, "sha256": actual_sha})

    canonical = json.dumps(
        {
            "commit": PINNED_COMMIT,
            "manifest_sha256": manifest_sha,
            "files": actual_digest_rows,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = sha256(canonical)
    return {"manifest_sha256": manifest_sha, "commit": PINNED_COMMIT}, digest


def _workflow_sha256() -> str:
    return sha256(_read_regular_file(WORKFLOW_FILE, "workflow source"))


def _load_components() -> tuple[Any, Any, Any, Any, list[dict[str, str]]]:
    analyzer_root = COPY_ROOT / "presidio-analyzer"
    anonymizer_root = COPY_ROOT / "presidio-anonymizer"
    sys.path[:0] = [str(analyzer_root), str(anonymizer_root)]
    try:
        from presidio_analyzer import PatternRecognizer
        from presidio_analyzer.predefined_recognizers.generic.email_recognizer import EmailRecognizer
        from presidio_anonymizer import AnonymizerEngine
    except Exception as exc:
        raise IntegrityError(f"cannot import the copied Presidio component: {exc}") from exc

    selected = [
        "presidio_analyzer",
        PatternRecognizer.__module__,
        EmailRecognizer.__module__,
        "presidio_anonymizer",
        AnonymizerEngine.__module__,
    ]
    import_rows: list[dict[str, str]] = []
    seen: set[str] = set()
    copy_resolved = COPY_ROOT.absolute()
    for name in selected:
        if name in seen:
            continue
        seen.add(name)
        module = importlib.import_module(name)
        file_value = getattr(module, "__file__", None)
        if not file_value:
            raise IntegrityError(f"copied Presidio import has no source file: {name}")
        module_path = Path(file_value).absolute()
        if not _inside(module_path, copy_resolved):
            raise IntegrityError(f"Presidio import resolved outside copied source: {name} -> {module_path}")
        import_rows.append(
            {
                "module": name,
                "path": module_path.relative_to(CANDIDATE_DIR.absolute()).as_posix(),
                "sha256": sha256(_read_regular_file(module_path, name)),
            }
        )

    patterns = EmailRecognizer.PATTERNS
    if not patterns:
        raise IntegrityError("the pinned EmailRecognizer has no configured pattern")
    pattern = patterns[0]
    recognizer = PatternRecognizer(supported_entity="EMAIL_ADDRESS", patterns=[pattern])
    return recognizer, pattern, AnonymizerEngine(), PatternRecognizer, import_rows


def _byte_offsets(text: str) -> list[int]:
    offsets = [0]
    for character in text:
        offsets.append(offsets[-1] + len(character.encode("utf-8", errors="strict")))
    return offsets


def _run_redaction(text: str, recognizer: Any, pattern: Any, engine: Any) -> tuple[list[dict[str, Any]], str]:
    results = recognizer.analyze(text, ["EMAIL_ADDRESS"])
    byte_offsets = _byte_offsets(text)
    findings: list[dict[str, Any]] = []
    for result in sorted(results, key=lambda item: (item.start, item.end, item.entity_type)):
        if (
            isinstance(result.start, bool)
            or isinstance(result.end, bool)
            or not isinstance(result.start, int)
            or not isinstance(result.end, int)
            or result.start < 0
            or result.end <= result.start
            or result.end > len(text)
        ):
            raise IntegrityError("Presidio returned an invalid character span")
        matched = text[result.start : result.end]
        findings.append(
            {
                "entity_type": result.entity_type,
                "start": result.start,
                "end": result.end,
                "utf8_start": byte_offsets[result.start],
                "utf8_end": byte_offsets[result.end],
                "score": float(result.score),
                "pattern_name": pattern.name,
                "matched_text_sha256": sha256(matched.encode("utf-8")),
            }
        )
    masked = engine.anonymize(text=text, analyzer_results=results).text
    return findings, masked


def _validate_findings_offsets(findings: Any, text: str) -> None:
    if not isinstance(findings, list):
        raise IntegrityError("proposal findings must be a list")
    offsets = _byte_offsets(text)
    byte_boundaries = set(offsets)
    expected_fields = {
        "entity_type",
        "start",
        "end",
        "utf8_start",
        "utf8_end",
        "score",
        "pattern_name",
        "matched_text_sha256",
    }
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict) or set(finding) != expected_fields:
            raise IntegrityError(f"finding {index} has an invalid shape")
        start, end = finding.get("start"), finding.get("end")
        if (
            isinstance(start, bool)
            or isinstance(end, bool)
            or not isinstance(start, int)
            or not isinstance(end, int)
            or start < 0
            or end <= start
            or end > len(text)
        ):
            raise IntegrityError(f"finding {index} has an invalid character offset")
        for name, char_index in (("utf8_start", start), ("utf8_end", end)):
            byte_index = finding.get(name)
            if isinstance(byte_index, bool) or not isinstance(byte_index, int) or byte_index not in byte_boundaries:
                raise IntegrityError(f"finding {index} {name} is not a UTF-8 character boundary")
            if byte_index != offsets[char_index]:
                raise IntegrityError(f"finding {index} {name} does not match its character offset")
        if finding.get("entity_type") != "EMAIL_ADDRESS":
            raise IntegrityError(f"finding {index} is outside the configured email-only scope")
        matched = text[start:end].encode("utf-8")
        if finding.get("matched_text_sha256") != sha256(matched):
            raise IntegrityError(f"finding {index} text digest does not match the current input")


def _artifact_path(path: str | Path, *, require_existing: bool) -> Path:
    root_value = Path(ARTIFACT_ROOT)
    if IMPROVED_DIR.is_symlink() or not IMPROVED_DIR.is_dir():
        raise IntegrityError("improved workflow directory is missing or unsafe")
    if root_value.is_symlink():
        raise IntegrityError("artifact directory must not be a symlink")
    if not root_value.exists():
        try:
            root_value.mkdir()
        except FileExistsError:
            pass
    if root_value.is_symlink() or not root_value.is_dir():
        raise IntegrityError("artifact directory is missing or unsafe")
    root = root_value.absolute()
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    candidate = Path(os.path.abspath(candidate))
    if candidate.parent != root or candidate.name in {"", ".", ".."}:
        raise IntegrityError("proposal and approved files must be direct children of the local artifacts directory")
    if candidate.is_symlink():
        raise IntegrityError(f"artifact file must not be a symlink: {candidate}")
    if require_existing and not candidate.is_file():
        raise IntegrityError(f"proposal file is missing or not regular: {candidate}")
    return candidate


def _write_exclusive(path: Path, data: bytes, label: str) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise IntegrityError(f"{label} already exists; refusing to overwrite: {path}") from exc
    except OSError as exc:
        raise IntegrityError(f"cannot create {label}: {exc}") from exc
    try:
        with os.fdopen(descriptor, "wb") as output:
            written = output.write(data)
            output.flush()
            os.fsync(output.fileno())
        if written != len(data):
            raise IntegrityError(f"short write while creating {label}")
    except OSError as exc:
        raise IntegrityError(f"cannot finish writing {label}: {exc}") from exc


def _json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def create_proposal(input_path: str | Path, proposal_path: str | Path) -> tuple[Path, str, dict[str, Any]]:
    target = _artifact_path(proposal_path, require_existing=False)
    source_info, source_digest = _manifest_and_source_digest()
    workflow_digest = _workflow_sha256()
    input_bytes, text = _read_utf8_input(input_path)
    recognizer, pattern, engine, _recognizer_class, imports = _load_components()
    findings, masked = _run_redaction(text, recognizer, pattern, engine)
    final_source_info, final_source_digest = _manifest_and_source_digest()
    if final_source_digest != source_digest or final_source_info != source_info:
        raise IntegrityError("copied Presidio source changed while preparing the proposal")
    if _workflow_sha256() != workflow_digest:
        raise IntegrityError("proposal workflow changed while preparing the proposal")
    if _read_utf8_input(input_path)[0] != input_bytes:
        raise IntegrityError("input changed while preparing the proposal")

    proposal = {
        "schema": PROPOSAL_SCHEMA,
        "source": {
            "repository": UPSTREAM_URL,
            "commit": source_info["commit"],
            "manifest_sha256": source_info["manifest_sha256"],
            "source_digest": source_digest,
        },
        "workflow_sha256": workflow_digest,
        "imports": imports,
        "input": {
            "sha256": sha256(input_bytes),
            "encoding": "UTF-8",
            "codepoint_length": len(text),
        },
        "findings": findings,
        "masked_output": masked,
        "masked_output_sha256": sha256(masked.encode("utf-8")),
        "scope": PROPOSAL_SCOPE,
    }
    data = _json_bytes(proposal)
    _write_exclusive(target, data, "proposal")
    return target, sha256(data), proposal


def approve_proposal(
    input_path: str | Path,
    proposal_path: str | Path,
    reviewed_sha256: str | None,
    approved_path: str | Path,
) -> tuple[Path, str, dict[str, Any]]:
    if not isinstance(reviewed_sha256, str) or not reviewed_sha256.strip():
        raise IntegrityError("explicit approval digest is required; no approved file was written")
    digest = reviewed_sha256.strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise IntegrityError("approval digest must be a 64-character SHA-256 hex value")

    proposal_file = _artifact_path(proposal_path, require_existing=True)
    approved_file = _artifact_path(approved_path, require_existing=False)
    proposal_bytes = _read_regular_file(proposal_file, "proposal")
    if sha256(proposal_bytes) != digest:
        raise IntegrityError("reviewed proposal SHA-256 does not match current proposal bytes")
    proposal = _load_json(proposal_bytes, "proposal")
    if not isinstance(proposal, dict) or set(proposal) != PROPOSAL_FIELDS:
        raise IntegrityError("proposal fields do not match the supported review schema")
    if proposal.get("schema") != PROPOSAL_SCHEMA:
        raise IntegrityError("proposal schema is unsupported")
    if proposal.get("scope") != PROPOSAL_SCOPE:
        raise IntegrityError("proposal scope differs from the supported email-only workflow")

    source_info, current_source_digest = _manifest_and_source_digest()
    current_workflow_digest = _workflow_sha256()
    source_record = proposal.get("source")
    if not isinstance(source_record, dict) or source_record != {
        "repository": UPSTREAM_URL,
        "commit": source_info["commit"],
        "manifest_sha256": source_info["manifest_sha256"],
        "source_digest": current_source_digest,
    }:
        raise IntegrityError("proposal is stale: copied Presidio source or pin has changed")
    if proposal.get("workflow_sha256") != current_workflow_digest:
        raise IntegrityError("proposal is stale: approval workflow source has changed")

    input_bytes, text = _read_utf8_input(input_path)
    input_record = proposal.get("input")
    if not isinstance(input_record, dict) or input_record != {
        "sha256": sha256(input_bytes),
        "encoding": "UTF-8",
        "codepoint_length": len(text),
    }:
        raise IntegrityError("proposal is stale: current input bytes differ from reviewed input")
    _validate_findings_offsets(proposal.get("findings"), text)

    recognizer, pattern, engine, _recognizer_class, imports = _load_components()
    findings, masked = _run_redaction(text, recognizer, pattern, engine)
    if proposal.get("imports") != imports:
        raise IntegrityError("proposal import paths or module digests differ from current copied source")
    if proposal.get("findings") != findings:
        raise IntegrityError("proposal findings differ from current Presidio detection results")
    if proposal.get("masked_output") != masked:
        raise IntegrityError("proposal masked output differs from current Presidio anonymization result")
    output_digest = sha256(masked.encode("utf-8"))
    if proposal.get("masked_output_sha256") != output_digest:
        raise IntegrityError("proposal masked output digest is invalid")
    if not findings:
        raise IntegrityError("no findings were detected; refusing to approve unchanged text")

    # Repeat all mutable evidence reads immediately before exclusive creation.
    if _read_regular_file(proposal_file, "proposal") != proposal_bytes:
        raise IntegrityError("proposal changed during approval; no approved file was written")
    if _read_utf8_input(input_path)[0] != input_bytes:
        raise IntegrityError("input changed during approval; no approved file was written")
    _final_source_info, final_source_digest = _manifest_and_source_digest()
    if final_source_digest != current_source_digest:
        raise IntegrityError("copied Presidio source changed during approval; no approved file was written")
    if _workflow_sha256() != current_workflow_digest:
        raise IntegrityError("approval workflow changed during approval; no approved file was written")

    approved = {
        "schema": APPROVED_SCHEMA,
        "proposal_sha256": digest,
        "source": source_record,
        "workflow_sha256": current_workflow_digest,
        "input_sha256": sha256(input_bytes),
        "findings": findings,
        "masked_output": masked,
        "masked_output_sha256": output_digest,
        "approval_record": {
            "method": "explicit local CLI invocation with caller-supplied proposal SHA-256",
            "human_identity_authenticated": False,
            "cryptographic_signature": False,
            "external_handoff": False,
        },
    }
    data = _json_bytes(approved)
    _write_exclusive(approved_file, data, "approved file")
    return approved_file, sha256(data), approved


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local synthetic-text Presidio proposal/approval example")
    subparsers = parser.add_subparsers(dest="command", required=True)
    propose_parser = subparsers.add_parser("propose", help="write a local redaction proposal")
    propose_parser.add_argument("--input", required=True, help="UTF-8 local input file")
    propose_parser.add_argument("--proposal", required=True, help="new file directly under improved/artifacts")
    approve_parser = subparsers.add_parser("approve", help="recheck and approve a reviewed proposal digest")
    approve_parser.add_argument("--input", required=True, help="same UTF-8 local input file")
    approve_parser.add_argument("--proposal", required=True, help="existing proposal under improved/artifacts")
    approve_parser.add_argument("--reviewed-sha256", help="digest reviewed locally before explicit approval")
    approve_parser.add_argument("--approved", required=True, help="new file directly under improved/artifacts")
    args = parser.parse_args(argv)
    try:
        if args.command == "propose":
            path, digest, proposal = create_proposal(args.input, args.proposal)
            print(
                json.dumps(
                    {"status": "proposal_written", "path": str(path), "proposal_sha256": digest,
                     "finding_count": len(proposal["findings"])},
                    sort_keys=True,
                )
            )
            return 0
        path, file_digest, approved = approve_proposal(
            args.input, args.proposal, args.reviewed_sha256, args.approved
        )
        print(
            json.dumps(
                {"status": "locally_approved", "path": str(path), "file_sha256": file_digest,
                 "proposal_sha256": approved["proposal_sha256"]},
                sort_keys=True,
            )
        )
        return 0
    except IntegrityError as exc:
        print(f"IntegrityError: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
