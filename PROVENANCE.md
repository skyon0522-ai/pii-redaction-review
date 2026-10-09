# Source provenance and adapter boundary

## Pinned component

This stage retains the complete copied Presidio Analyzer and Presidio Anonymizer package directories from [data-privacy-stack/presidio](https://github.com/data-privacy-stack/presidio), commit [`2523c7b74a469270c5c78bb253f140eafca21e31`](https://github.com/data-privacy-stack/presidio/commit/2523c7b74a469270c5c78bb253f140eafca21e31), dated 2026-10-08. Both package metadata files identify version 2.2.364. The upstream root MIT `LICENSE`, `NOTICE`, and README are retained inside `copied-component/`. No source file in those 467 manifest entries is adapted.

The unchanged [SOURCE_MANIFEST.json](SOURCE_MANIFEST.json) records 467 relative paths, original Git blob IDs and modes, byte counts, SHA-256 values, and the copied blob IDs. Its SHA-256 is `4c9f79a0bf666eb3ad7d77ddb5f4127cbbe4a47227a34796419dac624c08bba9`. The manifest records 464 files at mode `100644` and 3 at `100755`; those are Git mode records and should not be inferred from Windows filesystem attributes.

## Runtime binding

The wrapper imports these files from the retained copy:

- `copied-component/presidio-analyzer/presidio_analyzer/pattern_recognizer.py` provides `PatternRecognizer`.
- `copied-component/presidio-analyzer/presidio_analyzer/predefined_recognizers/generic/email_recognizer.py` provides the configured `EmailRecognizer.PATTERNS[0]` pattern; the wrapper does not instantiate or call `EmailRecognizer`.
- `copied-component/presidio-anonymizer/presidio_anonymizer/anonymizer_engine.py` provides `AnonymizerEngine`.

The focused run recorded imports from those exact copied paths. Their hashes and the two package `__init__.py` hashes are in [verification/receipt.json](verification/receipt.json). Presidio is therefore an executed source component here, not merely a declared dependency or a separately installed wheel. No original-versus-copy comparison is claimed by this stage; the one-fixture differential baseline is recorded privately in the prior source report.

## Small authored adapter

The private CLI and tests are retained at the stage root. Compared with the private wrapper, the only code adapter for this layout changes `CANDIDATE_DIR = IMPROVED_DIR.parent` to `CANDIDATE_DIR = IMPROVED_DIR`; the copied package and all 467 upstream blobs remain unchanged. The private wrapper SHA-256 was `cc877614580ea1647885e134d518fae93822a8ab287f827d5c0bab066a48c1a7`; the curated wrapper SHA-256 is `e76396a243c518f398a92f335fbed95c6647c4307c638414f96e477d8d901cff`. These are fingerprints, not confidentiality controls.

The run imports Python dependencies from the selected interpreter's existing environment. Package names and the versions loaded in the recorded environment are listed in [VERIFICATION.md](VERIFICATION.md). This bundle does not include a virtual environment, wheelhouse, model, native binary, or dependency installer.

## Research and license boundaries

This is an implementation example with a deterministic email pattern and local integrity checks. It makes no research-derived PII accuracy claim, so no research paper is cited. The upstream license and notice stay with the copied source. [LICENSE.authored](LICENSE.authored) applies only to this stage's authored CLI, tests, fixture, verifier, and documentation. See [NOTICE](NOTICE) for the file boundary; neither license reassigns authorship of the copied source.
