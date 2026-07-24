package clpe

import (
	"bytes"
	"fmt"
	"testing"
)

func fixedKek(string) ([]byte, error) { return bytes.Repeat([]byte{7}, 32), nil }

func TestEnvelopeRoundTrip(t *testing.T) {
	pt := []byte("Año señor € — log de prueba con UTF-8")
	ct, err := Encrypt(pt, "tenant-a", fixedKek)
	if err != nil {
		t.Fatal(err)
	}
	if !IsEnvelope(ct) {
		t.Fatal("falta el magic CLPE")
	}
	got, err := Decrypt(ct, fixedKek)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round-trip: %q != %q", got, pt)
	}
}

// Verifica el layout byte-a-byte (= formato del Encryptor Java -> interoperable).
func TestEnvelopeLayout(t *testing.T) {
	ct, err := Encrypt([]byte("x"), "tenant-a", fixedKek)
	if err != nil {
		t.Fatal(err)
	}
	if string(ct[:4]) != "CLPE" {
		t.Fatalf("magic: %q", ct[:4])
	}
	if ct[4] != 1 {
		t.Fatalf("version: %d", ct[4])
	}
	tenant := "tenant-a"
	if int(ct[5]) != len(tenant) {
		t.Fatalf("tenantLen: %d", ct[5])
	}
	if string(ct[6:6+len(tenant)]) != tenant {
		t.Fatalf("tenant: %q", ct[6:6+len(tenant)])
	}
}

func TestMaxEnvelopeOverhead(t *testing.T) {
	tenant := string(bytes.Repeat([]byte("t"), 255))
	plaintext := []byte("x")
	envelope, err := Encrypt(plaintext, tenant, fixedKek)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(envelope) - len(plaintext); got != MaxEnvelopeOverhead {
		t.Fatalf("overhead máximo=%d, constante=%d", got, MaxEnvelopeOverhead)
	}
}

func TestTamperFails(t *testing.T) {
	ct, _ := Encrypt([]byte("secreto"), "tenant-a", fixedKek)
	ct[len(ct)-1] ^= 0xFF // manipula el ciphertext
	if _, err := Decrypt(ct, fixedKek); err == nil {
		t.Fatal("GCM debería detectar la manipulación")
	}
}

func TestWrongKekFails(t *testing.T) {
	ct, _ := Encrypt([]byte("secreto"), "tenant-a", fixedKek)
	other := func(string) ([]byte, error) { return bytes.Repeat([]byte{9}, 32), nil }
	if _, err := Decrypt(ct, other); err == nil {
		t.Fatal("una KEK errónea debería fallar al descifrar")
	}
}

func TestEmptyAndBinary(t *testing.T) {
	for _, pt := range [][]byte{{}, bytes.Repeat([]byte{0, 1, 2, 255}, 4096)} {
		ct, err := Encrypt(pt, "t", fixedKek)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decrypt(ct, fixedKek)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("binario/vacío: %v", err)
		}
	}
}

func TestTruncatedEnvelopeNeverPanics(t *testing.T) {
	valid, err := Encrypt([]byte("secreto"), "tenant-a", fixedKek)
	if err != nil {
		t.Fatal(err)
	}
	for length := 0; length < len(valid); length++ {
		candidate := append([]byte(nil), valid[:length]...)
		t.Run(fmt.Sprintf("len_%d", length), func(t *testing.T) {
			if _, err := Decrypt(candidate, fixedKek); err == nil {
				t.Fatalf("sobre truncado de %d bytes debería fallar", length)
			}
		})
	}
}

func TestTenant(t *testing.T) {
	env, err := Encrypt([]byte("x"), "tenant-a", fixedKek)
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
