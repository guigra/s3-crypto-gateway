package main

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"testing"
	"time"
)

func TestTenantOf(t *testing.T) {
	cases := map[string]string{
		"ir-go/tenant-a/prod/k8s/ns/svc/pod/c/2026/06/17/x.jsonl.zst": "tenant-a",
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
	key := "ir-go/tenant-a/prod/k8s/ns/svc/pod/c/x"
	// global off
	if (Config{EncEnabled: false}).encEnabled(key) {
		t.Error("off global debería no cifrar")
	}
	// global on, sin filtros
	if !(Config{EncEnabled: true}).encEnabled(key) {
		t.Error("on global debería cifrar")
	}
	// filtro por tenant
	if !(Config{EncEnabled: true, EncTenants: []string{"tenant-a"}}).encEnabled(key) {
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

func TestLoadConfigRejectsInvalidSSEC(t *testing.T) {
	t.Setenv("SSEC_ENABLED", "true")
	t.Setenv("SSEC_KEY", "no-base64")
	if _, err := loadConfig(); err == nil {
		t.Fatal("SSE-C habilitado con clave inválida debería impedir el arranque")
	}

	t.Setenv("SSEC_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("configuración SSE-C válida: %v", err)
	}
	if cfg.ssec() == nil {
		t.Fatal("SSE-C válido debería estar activo")
	}
}

func TestLoadConfigRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"ENC_ENABLED", "enabled"},
		{"MAX_OBJECT_BYTES", "0"},
		{"READ_HEADER_TIMEOUT", "-1s"},
		{"READ_TIMEOUT", "mañana"},
		{"WRITE_TIMEOUT", "0s"},
		{"IDLE_TIMEOUT", "0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.name, tc.value)
			if _, err := loadConfig(); err == nil {
				t.Fatalf("%s=%q debería rechazarse", tc.name, tc.value)
			}
		})
	}
}

func TestLoadConfigLimitsAndTimeouts(t *testing.T) {
	t.Setenv("MAX_OBJECT_BYTES", "4096")
	t.Setenv("READ_HEADER_TIMEOUT", "3s")
	t.Setenv("READ_TIMEOUT", "4s")
	t.Setenv("WRITE_TIMEOUT", "5s")
	t.Setenv("IDLE_TIMEOUT", "6s")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxObjectBytes != 4096 ||
		cfg.ReadHeaderTimeout != 3*time.Second ||
		cfg.ReadTimeout != 4*time.Second ||
		cfg.WriteTimeout != 5*time.Second ||
		cfg.IdleTimeout != 6*time.Second {
		t.Fatalf("límites inesperados: %+v", cfg)
	}
}

func TestLoadConfigAllowedBuckets(t *testing.T) {
	t.Setenv("ALLOWED_BUCKETS", " logs-a, logs-b,logs-a ")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.AllowedBuckets) != 2 || cfg.AllowedBuckets[0] != "logs-a" || cfg.AllowedBuckets[1] != "logs-b" {
		t.Fatalf("allowlist inesperada: %#v", cfg.AllowedBuckets)
	}
	if !cfg.bucketAllowed("logs-a") || cfg.bucketAllowed("otro") {
		t.Fatal("la allowlist no se aplica correctamente")
	}
}

func TestLoadConfigRejectsMalformedAllowedBuckets(t *testing.T) {
	for _, value := range []string{" ", ",", " , , "} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("ALLOWED_BUCKETS", value)
			if _, err := loadConfig(); err == nil {
				t.Fatalf("ALLOWED_BUCKETS=%q debería impedir el arranque", value)
			}
		})
	}
}

func TestEmptyAllowedBucketsIsUnrestricted(t *testing.T) {
	t.Setenv("ALLOWED_BUCKETS", "")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.bucketAllowed("cualquier-bucket") {
		t.Fatal("una allowlist vacía debe mantener compatibilidad")
	}
}
