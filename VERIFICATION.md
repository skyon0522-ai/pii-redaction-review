# Verification record and limits

## Curated-stage run

The portable entry point is `verify.ps1`. It requires an explicit `-PythonCommand` value, accepts either a command available on PATH or an executable path, and does not install dependencies. On Windows it creates a temporary mapping for this stage on a free drive, records whether `subst` succeeded, and removes the mapping in `finally` only after successful creation; on other platforms it runs from the stage directory directly. It invokes the focused `unittest` file with bytecode writes disabled.

The curated stage was verified once with the bundled CPython 3.12.14 runtime and the pre-existing task-local dependency environment. The verifier selected a temporary drive mapping, which it removed after all six tests passed in 8.433 seconds. The test environment was reused; no packages, wheels, models, or native tools were installed or downloaded. The run left no artifacts or bytecode caches in this stage. The exact sanitized receipt is [verification/receipt.json](verification/receipt.json). This run predates the verifier cleanup fix below and remains historical evidence; its receipt file SHA-256 is `DD8C528BFFAABAB5B2A40758C25E285445F56915B4BBD846E9B69552E7DA2A15`. The receipt file is unchanged, and that hash is for the receipt JSON, not the current verifier.

## Verifier cleanup correction (2026-10-10)

The verifier now records successful mapping creation separately and attempts cleanup only when this invocation created the mapping. Its current SHA-256 is `D8C14DBCBA1A4854D4CDD8353D4CAE9748FEC4C704B17FDA5CE14F12CCB86FFA`.

A targeted branch check ran this `verify.ps1` with controlled PATH command stubs for mapping and Python execution, plus stubbed location push/pop. Failed creation returned exit code 1 after one creation attempt, with no cleanup call and no Python invocation. Successful creation returned exit code 0 after the stub recorded creation, the Python command arguments, and cleanup. The Python stub did not run tests, and the mapping stub did not create or remove a real drive mapping. The machine-readable receipt is [verifier-cleanup.json](verification/verifier-cleanup.json). The six-test suite was not rerun.

Observed versions in the reused environment were spaCy 3.8.16, regex 2026.9.29, tldextract 5.4.0, phonenumbers 9.0.41, NumPy 2.4.6, Pydantic 2.14.0, and PyYAML 6.0.3. The bundled runtime supplied cryptography 50.0.2. These observations are not a dependency lock; fresh environment installation has not been verified. The copied Analyzer and Anonymizer `pyproject.toml` files declare the direct dependency ranges. The exercised `PatternRecognizer` path did not load or download an NLP model.

The tests exercised proposal-only behavior, the separate approval command, missing and incorrect digests, the matching digest, stale source and input rejection, altered proposal/output rejection, invalid UTF-8 byte boundaries, exclusive output creation, and the phone-like non-email miss. They did not run the upstream Presidio test suite. The included source manifest checks all 467 copied files by byte count, SHA-256 and Git blob ID; the run's derived source digest is recorded in the receipt.

## Fresh Windows environment check (2026-10-10)

A separate isolated CPython 3.12.14 virtual environment installed the copied Analyzer and Anonymizer's declared dependency ranges from official PyPI, using `--no-cache-dir --only-binary=:all:`. It acquired 54 wheels and used no system site-packages. `pip check` passed. Five imported component paths and their hashes matched the copied source. No Presidio registry package or NLP model was installed.

The actual current `verify.ps1`, supplied with the fresh interpreter path, ran all six focused tests in 4.346 seconds and exited 0. Its temporary drive mapping was removed; all 481 published source files and the file set were unchanged afterward. The compact record is [verification/fresh-environment.json](verification/fresh-environment.json).

The earlier reused-environment run and stubbed cleanup-branch check above remain distinct historical results. This later run closes their fresh-install and real-verifier rerun gaps for this Windows/Python profile only. It does not establish other platforms, versions, general PII accuracy, full upstream coverage or network behavior. Dependency ranges remain unpinned; this record is not a lockfile.

## Focused no-network sentinel probe

A separate pre-curation probe completed one synthetic `create_proposal` and `approve_proposal` flow through the pinned copied component. Sentinels installed before importing the wrapper recorded zero calls to `tldextract.extract`, `socket.socket.connect`, and `socket.create_connection`. The probe also observed a proposal finding, a created approved record, and a matching proposal digest. The independent v3 receipt records the import paths and module hashes.

This result is limited to the tested code path and those three sentinels. It is not a general audit of all dependencies, runtime configurations, or network activity. The earlier independent v2 report recorded preflight/import errors at the longer path; v3 found the same files present and completed under a temporary short path. That is consistent with a Windows path-length issue, but no controlled threshold test isolated the cause. The source is present and remains unchanged.

The prior private baseline compared the pinned original and copied implementation on one synthetic email fixture and recorded matching detection and masking. This curation does not repeat that comparison. The independent source-review correction and v3 probe add evidence for call-path scope and the focused sentinel run; they do not establish production privacy or actual Human approval.

## Limits

This example uses one configured email pattern. The synthetic phone-like case has no finding and cannot be approved as unchanged input. Other unmatched sensitive text can remain in the masked output. The local caller-supplied SHA-256 does not authenticate a reviewer or provide a cryptographic signature. No production or external-service safety, Japanese/general PII accuracy, full dependency network behavior, full upstream regression coverage, remote CI, or customer use is claimed.
