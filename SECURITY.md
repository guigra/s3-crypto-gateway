# Security Policy

## Supported versions

Only the **latest release** receives security fixes. Verify what you run:
releases are keyless-signed (cosign/Rekor) with CycloneDX SBOM and SLSA L3
provenance — see the README's *Supply chain* section.

## Reporting a vulnerability

**Please do NOT open a public issue for security problems.**

Use GitHub's private vulnerability reporting: **Security tab → Report a
vulnerability** (or <https://github.com/guigra/s3-crypto-gateway/security/advisories/new>).

Include if possible: affected version/digest, reproduction steps, and impact
(e.g. plaintext exposure, KEK handling, envelope tampering). Reports touching
the cryptographic envelope (`pkg/clpe`) or SSE-C handling are especially
appreciated.

This is a solo-maintained project: acknowledgement is best-effort (normally
within a few days). Coordinated disclosure preferred — you will be credited in
the advisory unless you ask otherwise.
