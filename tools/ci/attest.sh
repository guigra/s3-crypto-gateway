#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# attest.sh — Cadena de suministro sobre una imagen YA PUSHEADA (firma + SBOM +
# provenance SLSA v0.2), con clave cosign. Reutilizable desde Jenkins, la VM de
# build o local. (En GitHub Actions NO se usa: allí la firma es keyless OIDC.)
#
#   uso:  tools/ci/attest.sh <imagen:tag>
#   env:  COSIGN_KEY=<ruta cosign.key>   COSIGN_PASSWORD=<passphrase>
#         SOURCE_URI=<repo git>  BUILDER_ID=<id del builder>  [TLOG=false]
#
# Gotcha Trivy (validado): el SBOM contra un registro Zot falla → se escanea el
# archive local (podman save). Requiere: podman, trivy, cosign, jq, git.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
IMG="${1:?uso: attest.sh <imagen:tag>}"
: "${COSIGN_KEY:?define COSIGN_KEY}"
: "${COSIGN_PASSWORD:?define COSIGN_PASSWORD}"
TLOG="${TLOG:-false}"
SOURCE_URI="${SOURCE_URI:-$(git config --get remote.origin.url 2>/dev/null || echo local)}"
BUILDER_ID="${BUILDER_ID:-urn:builder:jenkins}"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
export COSIGN_PASSWORD

echo ">> firma: $IMG"
cosign sign --key "$COSIGN_KEY" --tlog-upload="$TLOG" --yes "$IMG"

echo ">> SBOM CycloneDX (trivy sobre archive local)"
podman save --format docker-archive -o "$WORK/img.tar" "$IMG"
trivy image --input "$WORK/img.tar" --format cyclonedx --output "$WORK/sbom.cdx.json" --quiet
cosign attest --key "$COSIGN_KEY" --tlog-upload="$TLOG" --type cyclonedx \
  --predicate "$WORK/sbom.cdx.json" --yes "$IMG"
echo "   SBOM adjuntado y firmado"

echo ">> provenance SLSA v0.2 (in-toto)"
COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq -n --arg builder "$BUILDER_ID" --arg src "$SOURCE_URI" --arg commit "$COMMIT" --arg now "$NOW" '{
  builder: {id: $builder},
  buildType: "https://slsa.dev/container/v1",
  invocation: {configSource: {uri: $src, digest: {sha1: $commit}}},
  metadata: {buildFinishedOn: $now, reproducible: false},
  materials: [{uri: $src, digest: {sha1: $commit}}]
}' > "$WORK/provenance.json"
cosign attest --key "$COSIGN_KEY" --tlog-upload="$TLOG" --type slsaprovenance \
  --predicate "$WORK/provenance.json" --yes "$IMG"
echo "   provenance adjuntada y firmada"

# El SBOM se conserva junto al workspace si el caller define SBOM_OUT
[ -n "${SBOM_OUT:-}" ] && cp "$WORK/sbom.cdx.json" "$SBOM_OUT" && echo "   SBOM copiado a $SBOM_OUT"
echo "✅ supply-chain completa para $IMG"
