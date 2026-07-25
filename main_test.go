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
	envelope, err := clpe.Encrypt([]byte("secreto"), "tenant-a", "ir-go/tenant-a/object", kek)
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
