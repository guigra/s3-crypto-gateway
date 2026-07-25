package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/guigra/s3-crypto-gateway/pkg/clpe"
)

type fakeS3Backend struct {
	body []byte
	meta map[string]string
	ct   string
	err  error
}

func (f *fakeS3Backend) Get(context.Context, string, string, *SSEC, int64) ([]byte, map[string]string, string, error) {
	return append([]byte(nil), f.body...), f.meta, f.ct, f.err
}

func (*fakeS3Backend) Put(context.Context, string, string, []byte, map[string]string, string, *SSEC) error {
	return nil
}

func (*fakeS3Backend) Head(context.Context, string, string, *SSEC) (*s3.HeadObjectOutput, error) {
	return &s3.HeadObjectOutput{}, nil
}

func (*fakeS3Backend) Delete(context.Context, string, string) error { return nil }

func (*fakeS3Backend) List(context.Context, string, string, string, string, int32) (*s3.ListObjectsV2Output, error) {
	return &s3.ListObjectsV2Output{}, nil
}

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
		{"copy", http.MethodPut, "/bucket/key", map[string]string{"X-Amz-Copy-Source": "/source/key"}},
		{"multipart-init", http.MethodPost, "/bucket/key?uploads=", nil},
		{"multipart-part", http.MethodPut, "/bucket/key?partNumber=1&uploadId=id", nil},
		{"version", http.MethodGet, "/bucket/key?versionId=id", nil},
		{"checksum-crc32", http.MethodPut, "/bucket/key", map[string]string{"X-Amz-Checksum-Crc32": "value"}},
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

func TestParseByteRange(t *testing.T) {
	tests := []struct {
		value      string
		size       int64
		wantStart  int64
		wantEnd    int64
		shouldFail bool
	}{
		{"bytes=0-3", 10, 0, 3, false},
		{"bytes=4-", 10, 4, 9, false},
		{"bytes=-3", 10, 7, 9, false},
		{"bytes=0-99", 10, 0, 9, false},
		{"bytes=-99", 10, 0, 9, false},
		{"bytes=10-11", 10, 0, 0, true},
		{"bytes=4-3", 10, 0, 0, true},
		{"bytes=0-1,3-4", 10, 0, 0, true},
		{"items=0-1", 10, 0, 0, true},
		{"bytes=0-1", 0, 0, 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			start, end, err := parseByteRange(tc.value, tc.size)
			if tc.shouldFail {
				if err == nil {
					t.Fatalf("parseByteRange(%q, %d) debería fallar", tc.value, tc.size)
				}
				return
			}
			if err != nil || start != tc.wantStart || end != tc.wantEnd {
				t.Fatalf("parseByteRange(%q, %d)=(%d,%d,%v), want (%d,%d,nil)",
					tc.value, tc.size, start, end, err, tc.wantStart, tc.wantEnd)
			}
		})
	}
}

func TestGetRangeReturnsPlaintextSlice(t *testing.T) {
	gw := &Gateway{
		cfg: Config{MaxObjectBytes: 1024},
		s3:  &fakeS3Backend{body: []byte("0123456789"), ct: "text/plain"},
	}
	request := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	request.Header.Set("Range", "bytes=2-5")
	response := httptest.NewRecorder()

	gw.handle(response, request)

	if response.Code != http.StatusPartialContent {
		t.Fatalf("status=%d, want %d; body=%s", response.Code, http.StatusPartialContent, response.Body.String())
	}
	if response.Body.String() != "2345" {
		t.Fatalf("body=%q, want %q", response.Body.String(), "2345")
	}
	if got := response.Header().Get("Content-Range"); got != "bytes 2-5/10" {
		t.Fatalf("Content-Range=%q", got)
	}
	if got := response.Header().Get("Content-Length"); got != "4" {
		t.Fatalf("Content-Length=%q", got)
	}
}

func TestGetUnsatisfiableRange(t *testing.T) {
	gw := &Gateway{
		cfg: Config{MaxObjectBytes: 1024},
		s3:  &fakeS3Backend{body: []byte("short")},
	}
	request := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	request.Header.Set("Range", "bytes=99-100")
	response := httptest.NewRecorder()

	gw.handle(response, request)

	if response.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("status=%d, want %d", response.Code, http.StatusRequestedRangeNotSatisfiable)
	}
	if got := response.Header().Get("Content-Range"); got != "bytes */5" {
		t.Fatalf("Content-Range=%q", got)
	}
}

func TestGetETagConditions(t *testing.T) {
	body := []byte("contenido")
	etag := md5hex(body)
	tests := []struct {
		name       string
		header     string
		value      string
		wantStatus int
	}{
		{"if-match-ok", "If-Match", `"` + etag + `"`, http.StatusOK},
		{"if-match-fails", "If-Match", `"otro"`, http.StatusPreconditionFailed},
		{"if-none-match", "If-None-Match", `"` + etag + `"`, http.StatusNotModified},
		{"if-none-match-miss", "If-None-Match", `"otro"`, http.StatusOK},
		{"if-none-match-weak", "If-None-Match", `W/"` + etag + `"`, http.StatusNotModified},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gw := &Gateway{
				cfg: Config{MaxObjectBytes: 1024},
				s3:  &fakeS3Backend{body: body},
			}
			request := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
			request.Header.Set(tc.header, tc.value)
			response := httptest.NewRecorder()

			gw.handle(response, request)

			if response.Code != tc.wantStatus {
				t.Fatalf("status=%d, want %d; body=%s", response.Code, tc.wantStatus, response.Body.String())
			}
		})
	}
}

func TestValidatePutChecksums(t *testing.T) {
	body := []byte("contenido")
	md5Sum := md5.Sum(body)
	sha256Sum := sha256.Sum256(body)
	valid := http.Header{
		"Content-Md5":           []string{base64.StdEncoding.EncodeToString(md5Sum[:])},
		"X-Amz-Checksum-Sha256": []string{base64.StdEncoding.EncodeToString(sha256Sum[:])},
	}
	if err := validatePutChecksums(valid, body); err != nil {
		t.Fatalf("checksums válidos: %v", err)
	}

	for _, header := range []http.Header{
		{"Content-Md5": []string{base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, md5.Size))}},
		{"Content-Md5": []string{"no-base64"}},
		{"X-Amz-Checksum-Sha256": []string{base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, sha256.Size))}},
		{"X-Amz-Sdk-Checksum-Algorithm": []string{"SHA256"}},
	} {
		if err := validatePutChecksums(header, body); err == nil {
			t.Fatalf("checksum inválido debería fallar: %#v", header)
		}
	}
}
