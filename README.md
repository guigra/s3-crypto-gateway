# s3-crypto-gateway

**Zero-knowledge client-side encryption for any S3-compatible storage — as a transparent proxy.**

Point your S3 client at this gateway instead of your provider. **PUT → encrypts**,
**GET → decrypts**, HEAD/LIST/DELETE pass through. Your provider (AWS, Hetzner,
MinIO, Garage, Ceph…) only ever sees ciphertext. No SDK changes, no app changes:
it speaks the S3 API on both sides and re-signs requests with real credentials.

```
┌────────────┐   S3 API (plain)   ┌───────────────────┐   S3 API (ciphertext)   ┌─────────────┐
│ your app / │ ─────────────────► │ s3-crypto-gateway │ ──────────────────────► │ any S3      │
│ aws cli    │ ◄───────────────── │  AES-256-GCM      │ ◄────────────────────── │ provider    │
└────────────┘     decrypted      └───────────────────┘      stored encrypted   └─────────────┘
```

## Why

- **Sovereignty / zero-knowledge**: encryption keys never leave your infrastructure.
  The storage provider cannot read your data — validated: raw GET returns
  ciphertext (or HTTP 400 with the optional SSE-C layer enabled).
- **No application changes**: any S3 client works (AWS SDK, boto3, aws cli, rclone).
- **Selective**: encrypt everything, or scope by key prefix and/or tenant.
- **Two stackable layers**: an AES-256-GCM envelope (this gateway holds the keys)
  plus optional S3 SSE-C headers (provider encrypts at rest with a key it does not store).

## Envelope format (`CLPE2`)

Each object is encrypted with a random per-object 256-bit DEK; the DEK is wrapped
with the tenant's KEK. GCM authenticates everything (tampering fails the read).

```
magic(4)="CLPE" | ver(1)=2 | tenantLen(1) | tenant | ivDek(12) | dekCtLen(2 BE) | dekCt | ivData(12) | dataCt
```

The tenant is derived from the 2nd segment of the object key (`prefix/<tenant>/...`).
**CLPE2** binds the object's S3 key as GCM **AAD**: an envelope copied to a
different path fails to decrypt. (v2 replaces v1; v1 is no longer emitted or accepted.)

## Quickstart

```bash
podman build -t s3-crypto-gateway .
podman run -p 9000:9000 \
  -e AWS_ENDPOINT_URL=https://s3.your-provider.example \
  -e AWS_REGION=eu-central-1 \
  -e AWS_ACCESS_KEY_ID=... -e AWS_SECRET_ACCESS_KEY=... \
  -e ENC_ENABLED=true \
  -e SCG_KEK_TENANT_A=$(openssl rand -base64 32) \
  s3-crypto-gateway

# then point any S3 client at it (path-style):
aws s3 cp file.txt s3://my-bucket/ir/tenant-a/file.txt \
  --endpoint-url http://localhost:9000
```

## Configuration (env)

| Var | Meaning |
|---|---|
| `PORT` | listen port (default 9000) |
| `AWS_ENDPOINT_URL` / `AWS_REGION` / `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | the **real** S3 backend (requests are re-signed with the SDK) |
| `ENC_ENABLED` | `true`/`false` — envelope encryption on/off (off = transparent proxy) |
| `ENC_TENANTS` | CSV of tenants to encrypt; empty = all |
| `ENC_PREFIXES` | CSV of key prefixes to encrypt (e.g. `ir/,archives/`); empty = all |
| `SCG_KEK_<TENANT>` | base64 32-byte KEK per tenant (uppercased, `-`→`_`; `CLP_KEK_<TENANT>` accepted as a compatibility alias) |
| `SSEC_ENABLED` / `SSEC_KEY` | optional **SSE-C** layer (headers to the backend; stacks with the envelope) |
| `MAX_OBJECT_BYTES` | maximum accepted/returned plaintext object size (default 1 GiB; CLPE1 overhead is handled internally) |
| `READ_HEADER_TIMEOUT` / `READ_TIMEOUT` | inbound HTTP timeouts (default `10s` / `5m`) |
| `WRITE_TIMEOUT` / `IDLE_TIMEOUT` | outbound/idle HTTP timeouts (default `5m` / `1m`) |

Invalid booleans, limits or durations prevent startup. When `SSEC_ENABLED=true`,
`SSEC_KEY` must be valid base64 containing exactly 32 bytes; the gateway fails
closed instead of silently disabling SSE-C.

## Use as a Go library

The CLPE envelope is also importable — no proxy needed — from
`github.com/guigra/s3-crypto-gateway/pkg/clpe`:

```go
import "github.com/guigra/s3-crypto-gateway/pkg/clpe"

kek := func(tenant string) ([]byte, error) { return myKeyStore.Get(tenant) }

objectKey := "ir/tenant-a/…/x.clp.zst"               // the exact S3 key, bound as AAD
env, err := clpe.Encrypt(plaintext, "tenant-a", objectKey, kek) // seal
pt, err  := clpe.Decrypt(env, objectKey, kek)                   // open (fails on tampering / wrong KEK / wrong key)
ok       := clpe.IsEnvelope(data)                    // detect
```

The library never reads the environment: you supply keys via a `KekFn`
(env vars, Vault, KMS…). Docs: `pkg.go.dev/github.com/guigra/s3-crypto-gateway/pkg/clpe`.

## Design notes

- **Stateless synchronous transform** — no ring buffer: backpressure belongs
  upstream. Scale with replicas + HPA; AES-NI makes encryption cheap.
- Static Go binary (no cgo), UBI-micro runtime, runs as non-root (`USER 1001`).
- Reproducible build: pinned `go.sum` + `-mod=readonly`; `govulncheck` clean.
- Interoperable: the `CLPE` envelope is byte-compatible with the Java `Encryptor`
  used in [clp-log-tier](https://github.com/guigra/clp-log-tier), where this
  gateway encrypts CLP log archives end-to-end.

## Supply chain

Releases (`v*` tags) are built by GitHub Actions and published to `ghcr.io` with:
**keyless cosign signature** (Fulcio/Rekor), **CycloneDX SBOM** attestation, and
**SLSA Build Level 3 provenance** (slsa-github-generator). Verify any release:

```bash
cosign verify ghcr.io/guigra/s3-crypto-gateway@<digest> \
  --certificate-identity-regexp '^https://github.com/guigra/s3-crypto-gateway/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

A `Jenkinsfile` is included for corporate environments (key-based signing via
`tools/ci/attest.sh` — same chain, no OIDC required).

## Security review

The accepted findings, compatibility constraints and remediation roadmap from
the 2026-07-25 security review are tracked in
[`docs/security-review-2026-07-25.md`](docs/security-review-2026-07-25.md).
The document distinguishes immediate compatible fixes from the coordinated
SigV4 and CLPE2 design work.

## License

[MIT](LICENSE) © 2026 Ricardo Guillén Gracia.
