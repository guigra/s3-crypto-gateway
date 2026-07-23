# crypto-gateway (Go) — frontera S3 de cifrado. Binario estático (sin cgo),
# runtime UBI-micro (certificación Red Hat) + CA certs para el TLS a S3. Igual patrón que gateway-go.
# Bases PINEADAS por digest (reproducibilidad + supply chain; Dependabot las actualiza)
FROM golang:1.25-bookworm@sha256:ea341baa9bd5ba6784f6d7161ace70544349a6242d54d34a0fbfd2c4d51c9d58 AS build
WORKDIR /src
# Build REPRODUCIBLE: go.sum fijado + -mod=readonly (falla si el sum no cuadra, no re-tidy).
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY *.go ./
COPY pkg/ pkg/
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
RUN go build -trimpath -mod=readonly -ldflags="-s -w" -o /s3-crypto-gateway .

FROM registry.access.redhat.com/ubi9/ubi-micro:latest@sha256:b1e86b97028b8fcfb6d85f997c39e6b6b67496163ef8d80d243220a4918e8bef
COPY --from=build /s3-crypto-gateway /s3-crypto-gateway
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
EXPOSE 9000
USER 1001
ENTRYPOINT ["/s3-crypto-gateway"]
