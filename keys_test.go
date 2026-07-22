package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"testing"
)

func TestKekFor(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)

	// tenant con guion -> SCG_KEK_TENANT_A
	os.Setenv("SCG_KEK_TENANT_A", base64.StdEncoding.EncodeToString(key))
	defer os.Unsetenv("SCG_KEK_TENANT_A")
	got, err := KekFor("tenant-a")
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("KEK válida: %v", err)
	}
	// alias de compatibilidad CLP_KEK_<TENANT>
	os.Setenv("CLP_KEK_LEGACY", base64.StdEncoding.EncodeToString(key))
	defer os.Unsetenv("CLP_KEK_LEGACY")
	if got, err := KekFor("legacy"); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("alias CLP_KEK_: %v", err)
	}
	// SCG_ tiene prioridad si existen ambas
	other := bytes.Repeat([]byte{7}, 32)
	os.Setenv("SCG_KEK_BOTH", base64.StdEncoding.EncodeToString(key))
	os.Setenv("CLP_KEK_BOTH", base64.StdEncoding.EncodeToString(other))
	defer os.Unsetenv("SCG_KEK_BOTH")
	defer os.Unsetenv("CLP_KEK_BOTH")
	if got, _ := KekFor("both"); !bytes.Equal(got, key) {
		t.Fatal("SCG_KEK_ debe tener prioridad sobre CLP_KEK_")
	}
	if _, err := KekFor("inexistente"); err == nil {
		t.Fatal("debería faltar la KEK")
	}
	os.Setenv("SCG_KEK_BAD", "no-base64!!!")
	defer os.Unsetenv("SCG_KEK_BAD")
	if _, err := KekFor("bad"); err == nil {
		t.Fatal("base64 inválido debería fallar")
	}
	os.Setenv("SCG_KEK_SHORT", base64.StdEncoding.EncodeToString([]byte("corta")))
	defer os.Unsetenv("SCG_KEK_SHORT")
	if _, err := KekFor("short"); err == nil {
		t.Fatal("KEK de longitud != 32 debería fallar")
	}
}
