# Local PII redaction review example

This small Python example reuses Presidio's existing email pattern recognizer and anonymizer. It prepares a local redaction proposal, then writes a separate local output only after an explicit command supplies the SHA-256 digest of the proposal being reviewed. It reads and writes local files; it does not submit the input or output to an external service.

## Synthetic example

The included input is `é: qa.person@example.invalid`. On the recorded run, Presidio found one `EMAIL_ADDRESS` span at character offsets `[3, 28)` and UTF-8 byte offsets `[4, 29)`, with score `0.5`, and produced:

```text
é: <EMAIL_ADDRESS>
```

The offsets differ because `é` uses two UTF-8 bytes. The `example.invalid` address is synthetic. The output is a proposal; it is not automatically approved.

## Verify and try the two-step flow

Use PowerShell 7 and Python 3.10–3.14. The copied Analyzer metadata requires spaCy, NumPy, click, regex, tldextract, PyYAML, phonenumbers, and Pydantic within the ranges in `copied-component/presidio-analyzer/pyproject.toml`; the copied Anonymizer metadata requires cryptography within the range in `copied-component/presidio-anonymizer/pyproject.toml`. These are unpinned package ranges, not a lockfile. A fresh dependency installation has not been verified. The recorded run reused an existing task-local Python 3.12.14 environment. This example does not install or download an NLP model. The verifier takes the Python command or executable path explicitly, does not install packages, and runs the focused tests:

```powershell
pwsh ./verify.ps1 -PythonCommand python
```

On Windows, the verifier temporarily maps this stage to an available drive when it runs, then removes only the mapping it created. It does not change the Python environment. The run uses the selected interpreter's already available site-packages; dependency setup from a fresh environment remains unverified.

To prepare a proposal from the synthetic fixture:

```powershell
$PythonCommand = 'python'
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
