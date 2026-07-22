package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// KekFor: KEK (32 bytes) de un tenant desde env CLP_KEK_<TENANT> (base64), con el nombre en
// mayúsculas y '-' -> '_'. Paridad con el EnvKeyProvider del appender. En F2 esto
// se sustituye por Vault Transit (la KEK nunca sale de Vault) detrás de la misma firma KekFn.
func KekFor(tenant string) ([]byte, error) {
	if tenant == "" {
		return nil, fmt.Errorf("tenant vacío")
	}
	name := "CLP_KEK_" + strings.ToUpper(strings.ReplaceAll(tenant, "-", "_"))
	b64 := os.Getenv(name)
	if b64 == "" {
		return nil, fmt.Errorf("falta la KEK del tenant %q (env %s)", tenant, name)
	}
	kek, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("KEK %s no es base64 válido: %w", name, err)
	}
	if len(kek) != 32 {
		return nil, fmt.Errorf("KEK %s debe ser de 32 bytes (AES-256), tiene %d", name, len(kek))
	}
	return kek, nil
}
