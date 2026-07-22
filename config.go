package main

import (
	"crypto/md5"
	"encoding/base64"
	"strings"
)

// Config del gateway (por env). El cifrado es OPCIONAL y CONFIGURABLE: global, por tenant y por
// prefijo. Si EncEnabled=false → proxy transparente (passthrough sin cifrar).
// SSE-C es una capa OPCIONAL e INDEPENDIENTE (defensa en profundidad; NO sustituye al sobre).
type Config struct {
	Port        string
	EncEnabled  bool
	EncTenants  []string // vacío = todos los tenants
	EncPrefixes []string // vacío = todos los prefijos (p. ej. "ir-go/,archives/")
	SSECEnabled bool
	SSECKey     []byte // clave SSE-C de 32 bytes (la misma para PUT/GET; Hetzner no la guarda)
}

func loadConfig() Config {
	c := Config{
		Port:        env("PORT", "9000"),
		EncEnabled:  env("ENC_ENABLED", "false") == "true",
		EncTenants:  splitCSV(env("ENC_TENANTS", "")),
		EncPrefixes: splitCSV(env("ENC_PREFIXES", "")),
		SSECEnabled: env("SSEC_ENABLED", "false") == "true",
	}
	if k := strings.TrimSpace(env("SSEC_KEY", "")); k != "" {
		if raw, err := base64.StdEncoding.DecodeString(k); err == nil && len(raw) == 32 {
			c.SSECKey = raw
		}
	}
	return c
}

// SSEC: cabeceras SSE-C calculadas (algoritmo + clave base64 + MD5 base64) que el gateway añade a
// las peticiones a Hetzner. nil = SSE-C desactivado o clave inválida.
type SSEC struct{ Algorithm, KeyB64, KeyMD5B64 string }

func (c Config) ssec() *SSEC {
	if !c.SSECEnabled || len(c.SSECKey) != 32 {
		return nil
	}
	sum := md5.Sum(c.SSECKey)
	return &SSEC{
		Algorithm: "AES256",
		KeyB64:    base64.StdEncoding.EncodeToString(c.SSECKey),
		KeyMD5B64: base64.StdEncoding.EncodeToString(sum[:]),
	}
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// tenantOf: 2º segmento de la clave §7 (ir-go/{tenant}/{env}/...). De ahí sale la KEK.
func tenantOf(key string) string {
	parts := strings.SplitN(key, "/", 3)
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

// encEnabled: ¿se cifra este objeto? global AND (tenant permitido) AND (prefijo permitido).
func (c Config) encEnabled(key string) bool {
	if !c.EncEnabled {
		return false
	}
	if len(c.EncTenants) > 0 && !contains(c.EncTenants, tenantOf(key)) {
		return false
	}
	if len(c.EncPrefixes) > 0 && !hasAnyPrefix(key, c.EncPrefixes) {
		return false
	}
	return true
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func hasAnyPrefix(s string, ps []string) bool {
	for _, p := range ps {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
