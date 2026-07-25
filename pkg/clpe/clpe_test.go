package clpe

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"
)

func fixedKek(string) ([]byte, error) { return bytes.Repeat([]byte{7}, 32), nil }

// clave de objeto de ejemplo, atada como AAD (CLPE2).
const kObj = "ir-go/tenant-a/prod/svc/pod/2026/07/25/x.clp.zst"

func TestEnvelopeRoundTrip(t *testing.T) {
	pt := []byte("Año señor € — log de prueba con UTF-8")
	ct, err := Encrypt(pt, "tenant-a", kObj, fixedKek)
	if err != nil {
		t.Fatal(err)
	}
	if !IsEnvelope(ct) {
		t.Fatal("falta el magic CLPE")
	}
	got, err := Decrypt(ct, kObj, fixedKek)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round-trip: %q != %q", got, pt)
	}
}

// Verifica el layout byte-a-byte (= formato del Encryptor Java -> interoperable).
func TestEnvelopeLayout(t *testing.T) {
	ct, err := Encrypt([]byte("x"), "tenant-a", kObj, fixedKek)
	if err != nil {
		t.Fatal(err)
	}
	if string(ct[:4]) != "CLPE" {
		t.Fatalf("magic: %q", ct[:4])
	}
	if ct[4] != 2 {
		t.Fatalf("version: %d (CLPE2)", ct[4])
	}
	tenant := "tenant-a"
	if int(ct[5]) != len(tenant) {
		t.Fatalf("tenantLen: %d", ct[5])
	}
	if string(ct[6:6+len(tenant)]) != tenant {
		t.Fatalf("tenant: %q", ct[6:6+len(tenant)])
	}
}

// El objeto NO crece por atar AAD (el AAD se autentica, no se almacena).
func TestMaxEnvelopeOverhead(t *testing.T) {
	tenant := string(bytes.Repeat([]byte("t"), 255))
	plaintext := []byte("x")
	envelope, err := Encrypt(plaintext, tenant, kObj, fixedKek)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(envelope) - len(plaintext); got != MaxEnvelopeOverhead {
		t.Fatalf("overhead máximo=%d, constante=%d", got, MaxEnvelopeOverhead)
	}
}

func TestTamperFails(t *testing.T) {
	ct, _ := Encrypt([]byte("secreto"), "tenant-a", kObj, fixedKek)
	ct[len(ct)-1] ^= 0xFF // manipula el ciphertext
	if _, err := Decrypt(ct, kObj, fixedKek); err == nil {
		t.Fatal("GCM debería detectar la manipulación")
	}
}

func TestWrongKekFails(t *testing.T) {
	ct, _ := Encrypt([]byte("secreto"), "tenant-a", kObj, fixedKek)
	other := func(string) ([]byte, error) { return bytes.Repeat([]byte{9}, 32), nil }
	if _, err := Decrypt(ct, kObj, other); err == nil {
		t.Fatal("una KEK errónea debería fallar al descifrar")
	}
}

// CLPE2: un sobre copiado a OTRA ruta (objectKey distinto) NO descifra.
func TestWrongObjectKeyFails(t *testing.T) {
	ct, err := Encrypt([]byte("secreto"), "tenant-a", kObj, fixedKek)
	if err != nil {
		t.Fatal(err)
	}
	// misma KEK, mismo tenant, pero la ruta (AAD) cambió -> debe fallar
	if _, err := Decrypt(ct, "ir-go/tenant-a/prod/svc/pod/2026/07/25/OTRO.clp.zst", fixedKek); err == nil {
		t.Fatal("descifrar con otra clave de objeto (AAD) debería fallar")
	}
	// con la ruta correcta, descifra
	if _, err := Decrypt(ct, kObj, fixedKek); err != nil {
		t.Fatalf("con la clave correcta debería descifrar: %v", err)
	}
}

func TestEmptyAndBinary(t *testing.T) {
	for _, pt := range [][]byte{{}, bytes.Repeat([]byte{0, 1, 2, 255}, 4096)} {
		ct, err := Encrypt(pt, "t", kObj, fixedKek)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decrypt(ct, kObj, fixedKek)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("binario/vacío: %v", err)
		}
	}
}

func TestTruncatedEnvelopeNeverPanics(t *testing.T) {
	valid, err := Encrypt([]byte("secreto"), "tenant-a", kObj, fixedKek)
	if err != nil {
		t.Fatal(err)
	}
	for length := 0; length < len(valid); length++ {
		candidate := append([]byte(nil), valid[:length]...)
		t.Run(fmt.Sprintf("len_%d", length), func(t *testing.T) {
			if _, err := Decrypt(candidate, kObj, fixedKek); err == nil {
				t.Fatalf("sobre truncado de %d bytes debería fallar", length)
			}
		})
	}
}

// VECTOR CROSS-LENGUAJE (interop): descifra un sobre CLPE2 generado por la
// implementación Java (logback-clp-s3-appender/Encryptor). Mismos inputs fijos.
// Prueba la compatibilidad byte-a-byte en el sentido Java→Go.
func TestDecryptsJavaGeneratedEnvelope(t *testing.T) {
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i) // 0x00..0x1f
	}
	kekFn := func(string) ([]byte, error) { return kek, nil }
	objKey := "ir-go/tenant-a/prod/svc/pod/2026/07/25/x.clp.zst"
	javaVectorB64 := "Q0xQRQIIdGVuYW50LWFchUgWeXSuQAUL2eYAMOPOJMGkvBSmepkQAsEhvf+0NiD" +
		"rUjmyUmfBNbuZkLU7gAjs01JZER3p+VcKsK/WNHLao7o1nxepqHuBLKrLzS7SYNQ" +
		"NBbD0rXHxRxsVq+/wvV33O2iChYZB+pN7AZkO1lXUuQ=="
	env, err := base64.StdEncoding.DecodeString(javaVectorB64)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(env, objKey, kekFn)
	if err != nil {
		t.Fatalf("Go debería descifrar el sobre de Java: %v", err)
	}
	if string(got) != "hola CLPE2 — año €" {
		t.Fatalf("plaintext inesperado: %q", got)
	}
}

func TestTenant(t *testing.T) {
	env, err := Encrypt([]byte("x"), "tenant-a", kObj, fixedKek)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Tenant(env)
	if err != nil || got != "tenant-a" {
		t.Fatalf("Tenant()=(%q, %v)", got, err)
	}
	if _, err := Tenant([]byte("CLPE")); err == nil {
		t.Fatal("cabecera truncada debería fallar")
	}
}
