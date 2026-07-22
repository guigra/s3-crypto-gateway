# crypto-gateway (Go) — frontera S3 de cifrado. Binario estático (sin cgo),
# runtime UBI-micro (certificación Red Hat) + CA certs para el TLS a S3. Igual patrón que gateway-go.
FROM golang:1.25-bookworm AS build
WORKDIR /src
# Build REPRODUCIBLE: go.sum fijado + -mod=readonly (falla si el sum no cuadra, no re-tidy).
# govulncheck: limpio (no requiere bump de x/net; se queda en go 1.22).
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY *.go ./
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
RUN go build -trimpath -mod=readonly -ldflags="-s -w" -o /s3-crypto-gateway .

FROM registry.access.redhat.com/ubi9/ubi-micro:latest
COPY --from=build /s3-crypto-gateway /s3-crypto-gateway
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
EXPOSE 9000
USER 1001
ENTRYPOINT ["/s3-crypto-gateway"]
