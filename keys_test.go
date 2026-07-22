package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"testing"
)

func TestKekFor(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	os.Setenv("CLP_KEK_ACMECORP", base64.StdEncoding.EncodeToString(key))
	defer os.Unsetenv("CLP_KEK_ACMECORP")

	got, err := KekFor("acmecorp")
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("KEK válida: %v", err)
	}
	// tenant con guion -> CLP_KEK_FASE_D
	os.Setenv("CLP_KEK_FASE_D", base64.StdEncoding.EncodeToString(key))
	defer os.Unsetenv("CLP_KEK_FASE_D")
	if _, err := KekFor("fase-d"); err != nil {
		t.Fatalf("guion->_ : %v", err)
	}
	if _, err := KekFor("inexistente"); err == nil {
		t.Fatal("debería faltar la KEK")
	}
	os.Setenv("CLP_KEK_BAD", "no-base64!!!")
	defer os.Unsetenv("CLP_KEK_BAD")
	if _, err := KekFor("bad"); err == nil {
		t.Fatal("base64 inválido debería fallar")
	}
	os.Setenv("CLP_KEK_SHORT", base64.StdEncoding.EncodeToString([]byte("corta")))
	defer os.Unsetenv("CLP_KEK_SHORT")
	if _, err := KekFor("short"); err == nil {
		t.Fatal("KEK de longitud != 32 debería fallar")
	}
}
