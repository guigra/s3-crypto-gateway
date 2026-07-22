package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// KekFor: KEK (32 bytes) de un tenant desde env SCG_KEK_<TENANT> (base64), con el nombre en
// mayúsculas y '-' -> '_'. Se acepta CLP_KEK_<TENANT> como alias de compatibilidad (paridad
// con el EnvKeyProvider del appender Java de clp-log-tier). En una fase futura esto se
// sustituye por Vault Transit (la KEK nunca sale de Vault) detrás de la misma firma KekFn.
func KekFor(tenant string) ([]byte, error) {
	if tenant == "" {
		return nil, fmt.Errorf("tenant vacío")
	}
	suffix := strings.ToUpper(strings.ReplaceAll(tenant, "-", "_"))
	name := "SCG_KEK_" + suffix
	b64 := os.Getenv(name)
	if b64 == "" { // alias de compatibilidad
		name = "CLP_KEK_" + suffix
		b64 = os.Getenv(name)
	}
	if b64 == "" {
		return nil, fmt.Errorf("falta la KEK del tenant %q (env SCG_KEK_%s o CLP_KEK_%s)", tenant, suffix, suffix)
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
