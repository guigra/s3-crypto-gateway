package main

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"testing"
)

func TestTenantOf(t *testing.T) {
	cases := map[string]string{
		"ir-go/acmecorp/prod/k8s/ns/svc/pod/c/2026/06/17/x.jsonl.zst": "acmecorp",
		"archives/maple/prod/2026/06/17/a":                            "maple",
		"ir-go":                                                       "",
		"":                                                            "",
	}
	for k, want := range cases {
		if got := tenantOf(k); got != want {
			t.Errorf("tenantOf(%q)=%q, want %q", k, got, want)
		}
	}
}

func TestEncEnabled(t *testing.T) {
	key := "ir-go/acmecorp/prod/k8s/ns/svc/pod/c/x"
	// global off
	if (Config{EncEnabled: false}).encEnabled(key) {
		t.Error("off global debería no cifrar")
	}
	// global on, sin filtros
	if !(Config{EncEnabled: true}).encEnabled(key) {
		t.Error("on global debería cifrar")
	}
	// filtro por tenant
	if !(Config{EncEnabled: true, EncTenants: []string{"acmecorp"}}).encEnabled(key) {
		t.Error("tenant permitido")
	}
	if (Config{EncEnabled: true, EncTenants: []string{"maple"}}).encEnabled(key) {
		t.Error("tenant NO permitido no cifra")
	}
	// filtro por prefijo
	if !(Config{EncEnabled: true, EncPrefixes: []string{"ir-go/", "archives/"}}).encEnabled(key) {
		t.Error("prefijo permitido")
	}
	if (Config{EncEnabled: true, EncPrefixes: []string{"archives/"}}).encEnabled(key) {
		t.Error("prefijo NO permitido no cifra")
	}
}

func TestSSEC(t *testing.T) {
	if (Config{SSECEnabled: false}).ssec() != nil {
		t.Error("SSE-C off -> nil")
	}
	if (Config{SSECEnabled: true, SSECKey: nil}).ssec() != nil {
		t.Error("SSE-C sin clave válida -> nil")
	}
	key := bytes.Repeat([]byte{5}, 32)
	s := (Config{SSECEnabled: true, SSECKey: key}).ssec()
	if s == nil || s.Algorithm != "AES256" {
		t.Fatalf("algoritmo: %+v", s)
	}
	if s.KeyB64 != base64.StdEncoding.EncodeToString(key) {
		t.Error("KeyB64 incorrecta")
	}
	sum := md5.Sum(key)
	if s.KeyMD5B64 != base64.StdEncoding.EncodeToString(sum[:]) {
		t.Error("KeyMD5B64 incorrecta")
	}
}
