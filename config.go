package main

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/guigra/s3-crypto-gateway/pkg/clpe"
)

const (
	defaultMaxObjectBytes  = int64(1 << 30) // 1 GiB
	defaultReadHeaderLimit = 10 * time.Second
	defaultReadTimeout     = 5 * time.Minute
	defaultWriteTimeout    = 5 * time.Minute
	defaultIdleTimeout     = 60 * time.Second
)

// Config del gateway (por env). El cifrado es OPCIONAL y CONFIGURABLE: global, por tenant y por
// prefijo. Si EncEnabled=false → proxy transparente (passthrough sin cifrar).
// SSE-C es una capa OPCIONAL e INDEPENDIENTE (defensa en profundidad; NO sustituye al sobre).
type Config struct {
	Port              string
	EncEnabled        bool
	EncTenants        []string // vacío = todos los tenants
	EncPrefixes       []string // vacío = todos los prefijos (p. ej. "ir-go/,archives/")
	SSECEnabled       bool
	SSECKey           []byte // clave SSE-C de 32 bytes (la misma para PUT/GET; Hetzner no la guarda)
	MaxObjectBytes    int64
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
}

func loadConfig() (Config, error) {
	encEnabled, err := envBool("ENC_ENABLED", false)
	if err != nil {
		return Config{}, err
	}
	ssecEnabled, err := envBool("SSEC_ENABLED", false)
	if err != nil {
		return Config{}, err
	}
	c := Config{
		Port:              env("PORT", "9000"),
		EncEnabled:        encEnabled,
		EncTenants:        splitCSV(env("ENC_TENANTS", "")),
		EncPrefixes:       splitCSV(env("ENC_PREFIXES", "")),
		SSECEnabled:       ssecEnabled,
		MaxObjectBytes:    defaultMaxObjectBytes,
		ReadHeaderTimeout: defaultReadHeaderLimit,
		ReadTimeout:       defaultReadTimeout,
		WriteTimeout:      defaultWriteTimeout,
		IdleTimeout:       defaultIdleTimeout,
	}
	if c.MaxObjectBytes, err = envPositiveInt64("MAX_OBJECT_BYTES", c.MaxObjectBytes); err != nil {
		return Config{}, err
	}
	for name, target := range map[string]*time.Duration{
		"READ_HEADER_TIMEOUT": &c.ReadHeaderTimeout,
		"READ_TIMEOUT":        &c.ReadTimeout,
		"WRITE_TIMEOUT":       &c.WriteTimeout,
		"IDLE_TIMEOUT":        &c.IdleTimeout,
	} {
		if *target, err = envPositiveDuration(name, *target); err != nil {
			return Config{}, err
		}
	}
	if c.SSECEnabled {
		k := strings.TrimSpace(env("SSEC_KEY", ""))
		raw, decodeErr := base64.StdEncoding.DecodeString(k)
		if decodeErr != nil || len(raw) != 32 {
			return Config{}, fmt.Errorf("SSEC_ENABLED=true requiere SSEC_KEY en base64 de exactamente 32 bytes")
		}
		c.SSECKey = raw
	}
	return c, nil
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

func envBool(name string, defaultValue bool) (bool, error) {
	value := strings.TrimSpace(env(name, strconv.FormatBool(defaultValue)))
	switch strings.ToLower(value) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("%s debe ser true o false", name)
	}
}

func envPositiveInt64(name string, defaultValue int64) (int64, error) {
	value := strings.TrimSpace(env(name, strconv.FormatInt(defaultValue, 10)))
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 || parsed > math.MaxInt64-clpe.MaxEnvelopeOverhead {
		return 0, fmt.Errorf("%s debe estar entre 1 y %d", name, int64(math.MaxInt64-clpe.MaxEnvelopeOverhead))
	}
	return parsed, nil
}

func envPositiveDuration(name string, defaultValue time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(env(name, defaultValue.String()))
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s debe ser una duración positiva (por ejemplo, 10s o 5m)", name)
	}
	return parsed, nil
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
