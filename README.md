# Local PII redaction review example

This small Python example reuses Presidio's existing email pattern recognizer and anonymizer. It prepares a local redaction proposal, then writes a separate local output only after an explicit command supplies the SHA-256 digest of the proposal being reviewed. It reads and writes local files; it does not submit the input or output to an external service.

## Find the relevant part

| Need | Start here |
| --- | --- |
| See the redacted sample and approval result | [Synthetic example](#synthetic-example) and [the fixture](examples/synthetic-email.txt) |
| Reproduce the proposal and reviewed write | [Verify and try the two-step flow](#verify-and-try-the-two-step-flow) and [CLI](redaction_cli.py) |
| Check the executed source, tests and limits | [Provenance](PROVENANCE.md), [verification](VERIFICATION.md), [focused tests](test_redaction_cli.py) and [limits](#limits) |
| Report a bug or security concern safely | [Security and reporting](SECURITY.md) |

## Synthetic example

The included input is `é: qa.person@example.invalid`. On the recorded run, Presidio found one `EMAIL_ADDRESS` span at character offsets `[3, 28)` and UTF-8 byte offsets `[4, 29)`, with score `0.5`, and produced:

```text
é: <EMAIL_ADDRESS>
```

The offsets differ because `é` uses two UTF-8 bytes. The `example.invalid` address is synthetic. The output is a proposal; it is not automatically approved.

## Verify and try the two-step flow

The locally verified profile is Windows x64, CPython 3.12.14, and PowerShell 7. [requirements-windows-py312.lock](requirements-windows-py312.lock) pins all 54 direct and transitive runtime packages to the versions and official-PyPI wheel hashes observed in the earlier [fresh-environment run](verification/fresh-environment.json). The wheel lock targets Windows x64 and CPython 3.12; it is not a cross-platform lock. No Presidio registry package or NLP model is installed. From a checkout, create a fresh environment, install the locked wheels, and run the existing verifier:

```powershell
python -I -m venv .venv
$PythonCommand = Join-Path $PWD '.venv/Scripts/python.exe'
& $PythonCommand -I -m pip install --index-url https://pypi.org/simple --require-hashes --no-cache-dir --only-binary=:all: -r requirements-windows-py312.lock
& $PythonCommand -I -m pip check
pwsh -NoProfile -File ./verify.ps1 -PythonCommand $PythonCommand
```

The [Windows workflow](.github/workflows/windows-verify.yml) selects CPython 3.12.10, the available official Windows 3.12 build, and uses the same locked install, `pip check`, and verifier with `contents: read` permission and action commit pins. Local results and remote CI status are recorded separately in [VERIFICATION.md](VERIFICATION.md).

On Windows, the verifier temporarily maps this stage to an available drive when it runs, then removes only the mapping it created. It does not change the Python environment. The verifier uses the selected interpreter's already available site-packages. Set up dependencies before running it; the verifier itself does not create an environment or download packages.

To prepare a proposal from the synthetic fixture:

```powershell
$Proposal = & $PythonCommand -B ./redaction_cli.py propose `
  --input ./examples/synthetic-email.txt `
  --proposal ./artifacts/proposal.json | ConvertFrom-Json
$Proposal
Get-Content -Raw ./artifacts/proposal.json
```

Review the proposal file, including its masked output. The output can still contain text that the one configured pattern did not detect. To create a separate approved record, pass the proposal digest after review:

```powershell
& $PythonCommand -B ./redaction_cli.py approve `
  --input ./examples/synthetic-email.txt `
  --proposal ./artifacts/proposal.json `
  --reviewed-sha256 '<reviewed proposal SHA-256>' `
  --approved ./artifacts/approved.json
```

Both output paths must be new direct children of `artifacts/`; existing files are never overwritten. Missing or mismatched digests, changed input or proposal, stale source, invalid offsets, and changed detector output fail with an integrity error. The digest binds exact bytes, but it does not identify the reviewer.

## Source and design

`redaction_cli.py` puts the copied package directories on the import path, reads `EmailRecognizer.PATTERNS[0]` as configuration for the copied `PatternRecognizer`, and passes detected spans to the copied `AnonymizerEngine`. It does not instantiate `EmailRecognizer`, use `AnalyzerEngine`, or load an NLP model. The complete 467-file copied component and its source manifest are in `copied-component/` and `SOURCE_MANIFEST.json`.

Read [PROVENANCE.md](PROVENANCE.md), [VERIFICATION.md](VERIFICATION.md), and [NOTICE](NOTICE) before adapting or redistributing this example. No research paper is offered as evidence that this email-only pattern provides reliable privacy protection; the synthetic tests are engineering checks, not a research validation study.

## Limits

The CLI accepts a local UTF-8 file and does not check whether it contains synthetic text. Tests here use synthetic text only. The deliberate phone-like non-email input passes through unchanged, and other undetected sensitive content can remain in the output. This example does not establish name, phone, Japanese, adversarial, or general PII accuracy and must not be treated as proof that text is safe to send to an external AI service.

The caller-supplied SHA-256 is unkeyed. It is not a cryptographic signature, user authentication, or proof of actual Human approval. Source, input, proposal and output hashes are change-detection fingerprints; they do not conceal or encrypt their contents. Do not use real or customer data in this example.
