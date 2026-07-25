package main

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guigra/s3-crypto-gateway/pkg/clpe"
)

func TestValidateEnvelopeTenant(t *testing.T) {
	kek := func(string) ([]byte, error) { return bytes.Repeat([]byte{7}, 32), nil }
	envelope, err := clpe.Encrypt([]byte("secreto"), "tenant-a", kek)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEnvelopeTenant(envelope, "ir-go/tenant-a/object"); err != nil {
		t.Fatalf("tenant coincidente: %v", err)
	}
	if err := validateEnvelopeTenant(envelope, "ir-go/tenant-b/object"); err == nil {
		t.Fatal("tenant diferente debería rechazarse")
	}
	if err := validateEnvelopeTenant([]byte("CLPE"), "ir-go/tenant-a/object"); err == nil {
		t.Fatal("sobre truncado debería rechazarse")
	}
}

func TestPutRejectsOversizedBodyBeforeS3(t *testing.T) {
	gw := &Gateway{cfg: Config{MaxObjectBytes: 4}}
	request := httptest.NewRequest(http.MethodPut, "/bucket/key", strings.NewReader("12345"))
	response := httptest.NewRecorder()

	gw.put(request.Context(), response, request, "bucket", "key")

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d, want %d", response.Code, http.StatusRequestEntityTooLarge)
	}
	if !strings.Contains(response.Body.String(), "EntityTooLarge") {
		t.Fatalf("respuesta inesperada: %s", response.Body.String())
	}
}

func TestInternalErrorIsSanitized(t *testing.T) {
	var logs bytes.Buffer
	previousWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previousWriter) })

	response := httptest.NewRecorder()
	internalErr(response, 502, "UpstreamError", "mensaje público", io.ErrUnexpectedEOF)

	if strings.Contains(response.Body.String(), io.ErrUnexpectedEOF.Error()) {
		t.Fatalf("la respuesta filtró el error interno: %s", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "mensaje público") {
		t.Fatalf("falta el mensaje público: %s", response.Body.String())
	}
	if !strings.Contains(logs.String(), io.ErrUnexpectedEOF.Error()) {
		t.Fatalf("el detalle no quedó en logs: %s", logs.String())
	}
	if response.Header().Get("X-Amz-Request-Id") == "" {
		t.Fatal("falta el identificador de correlación")
	}
}

func TestUnsupportedFeatures(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		target  string
		headers map[string]string
	}{
		{"range", http.MethodGet, "/bucket/key", map[string]string{"Range": "bytes=0-9"}},
		{"conditional", http.MethodGet, "/bucket/key", map[string]string{"If-Match": `"etag"`}},
		{"copy", http.MethodPut, "/bucket/key", map[string]string{"X-Amz-Copy-Source": "/source/key"}},
		{"multipart-init", http.MethodPost, "/bucket/key?uploads=", nil},
		{"multipart-part", http.MethodPut, "/bucket/key?partNumber=1&uploadId=id", nil},
		{"version", http.MethodGet, "/bucket/key?versionId=id", nil},
		{"checksum", http.MethodPut, "/bucket/key", map[string]string{"X-Amz-Checksum-Sha256": "value"}},
		{"acl-header", http.MethodPut, "/bucket/key", map[string]string{"X-Amz-Acl": "private"}},
		{"client-sse", http.MethodPut, "/bucket/key", map[string]string{"X-Amz-Server-Side-Encryption": "AES256"}},
		{"content-encoding", http.MethodPut, "/bucket/key", map[string]string{"Content-Encoding": "gzip"}},
		{"head-bucket", http.MethodHead, "/bucket", nil},
		{"create-bucket", http.MethodPut, "/bucket", nil},
		{"list-v1", http.MethodGet, "/bucket", nil},
		{"list-v2-extra", http.MethodGet, "/bucket?list-type=2&fetch-owner=true", nil},
	}
	gw := &Gateway{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(tc.method, tc.target, nil)
			for name, value := range tc.headers {
				request.Header.Set(name, value)
			}
			response := httptest.NewRecorder()

			gw.handle(response, request)

			if response.Code != http.StatusNotImplemented {
				t.Fatalf("status=%d, want %d; body=%s", response.Code, http.StatusNotImplemented, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), "NotImplemented") {
				t.Fatalf("respuesta inesperada: %s", response.Body.String())
			}
		})
	}
}

func TestInvalidRootPath(t *testing.T) {
	response := httptest.NewRecorder()
	(&Gateway{}).handle(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestListV2ContractIsAccepted(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/bucket?list-type=2&prefix=logs/&max-keys=10", nil)
	if feature := unsupportedFeature(request, ""); feature != "" {
		t.Fatalf("ListObjectsV2 válido rechazado: %s", feature)
	}
}
