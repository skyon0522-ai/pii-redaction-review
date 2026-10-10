# Security and reporting

This is a local, synthetic-data example using one email pattern. It can miss sensitive content, and masked output can retain that content. SHA-256 checks detect changed bytes; they do not encrypt data, authenticate a reviewer, or prove Human approval. Do not use real, customer, credential, or confidential data. See [the limits](README.md#limits).

For a reproducible bug that can be described safely with invented text, open a [public Issue](https://github.com/skyon0522-ai/pii-redaction-review/issues/new). Include the affected commit, Windows/Python versions, commands, expected result, and a minimal synthetic example. Public issues, logs, screenshots, proposals, and approved files must not include sensitive data.

GitHub private vulnerability reporting was checked on 2026-10-11 and is disabled for this repository. No private reporting address is advertised. If a security finding requires confidential details, retain those details privately and open only a neutral public Issue asking the maintainer to enable private vulnerability reporting. Do not include the vulnerability, affected data, or an exploit in that request. Wait for a verified private channel before sharing details.

For changes to the copied Presidio component, retain its [license and provenance](PROVENANCE.md). This example has no promised security response time or production support policy.
