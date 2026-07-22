// Package clpe implements the CLPE envelope: authenticated per-object envelope
// encryption (AES-256-GCM) with multi-tenant key wrapping.
//
// Each payload is encrypted with a random 256-bit DEK; the DEK is wrapped with
// the tenant's KEK. GCM authenticates everything, so any tampering fails on
// decrypt. The wire format is byte-compatible with the Java Encryptor used in
// clp-log-tier, so both implementations interoperate:
//
//	magic(4)="CLPE" | ver(1)=1 | tenantLen(1)|tenant | ivDek(12) | dekCtLen(2 BE)|dekCt
//	| ivData(12) | dataCt(rest)
//
// Callers provide key material via a KekFn (env vars, Vault, KMS, …); the
// library never reads the environment itself.
package clpe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

var clpeMagic = []byte("CLPE")

const (
	clpeVersion = 1
	ivLen       = 12 // nonce GCM
	dekLen      = 32 // AES-256
)

// KekFn returns the 32-byte KEK for a tenant.
type KekFn func(tenant string) ([]byte, error)

// IsEnvelope reports whether b starts with the CLPE magic (e.g. to decide
// whether a fetched object needs decryption).
func IsEnvelope(b []byte) bool { return len(b) >= 4 && string(b[:4]) == "CLPE" }

// Encrypt seals pt into a CLPE envelope under the tenant's KEK.
func Encrypt(pt []byte, tenant string, kekFor KekFn) ([]byte, error) {
	if len(tenant) > 255 {
		return nil, errors.New("tenant demasiado largo (>255)")
	}
	kek, err := kekFor(tenant)
	if err != nil {
		return nil, err
	}
	if len(kek) != dekLen {
		return nil, errors.New("KEK debe ser de 32 bytes")
	}
	dek, err := randBytes(dekLen)
	if err != nil {
		return nil, err
	}
	ivData, err := randBytes(ivLen)
	if err != nil {
		return nil, err
	}
	dataCt, err := gcmSeal(dek, ivData, pt)
	if err != nil {
		return nil, err
	}
	ivDek, err := randBytes(ivLen)
	if err != nil {
		return nil, err
	}
	dekCt, err := gcmSeal(kek, ivDek, dek)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, 4+1+1+len(tenant)+ivLen+2+len(dekCt)+ivLen+len(dataCt))
	out = append(out, clpeMagic...)
	out = append(out, clpeVersion)
	out = append(out, byte(len(tenant)))
	out = append(out, tenant...)
	out = append(out, ivDek...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(dekCt)))
	out = append(out, dekCt...)
	out = append(out, ivData...)
	out = append(out, dataCt...)
	return out, nil
}

// Decrypt opens a CLPE envelope. It fails if the envelope was tampered with
// or the KEK is wrong.
func Decrypt(env []byte, kekFor KekFn) ([]byte, error) {
	if !IsEnvelope(env) {
		return nil, errors.New("magic CLPE inválido")
	}
	p := 4
	if env[p] != clpeVersion {
		return nil, errors.New("versión CLPE no soportada")
	}
	p++
	if p >= len(env) {
		return nil, errors.New("sobre truncado (tenantLen)")
	}
	tLen := int(env[p])
	p++
	if p+tLen+ivLen+2 > len(env) {
		return nil, errors.New("sobre truncado (cabecera)")
	}
	tenant := string(env[p : p+tLen])
	p += tLen
	ivDek := env[p : p+ivLen]
	p += ivLen
	dekCtLen := int(binary.BigEndian.Uint16(env[p : p+2]))
	p += 2
	if p+dekCtLen+ivLen > len(env) {
		return nil, errors.New("sobre truncado (dekCt/ivData)")
	}
	dekCt := env[p : p+dekCtLen]
	p += dekCtLen
	ivData := env[p : p+ivLen]
	p += ivLen
	dataCt := env[p:]

	kek, err := kekFor(tenant)
	if err != nil {
		return nil, err
	}
	if len(kek) != dekLen {
		return nil, errors.New("KEK debe ser de 32 bytes")
	}
	dek, err := gcmOpen(kek, ivDek, dekCt)
	if err != nil {
		return nil, errors.New("fallo al desenvolver la DEK (¿KEK errónea o sobre manipulado?)")
	}
	return gcmOpen(dek, ivData, dataCt)
}

// --- helpers AES-GCM ---
func gcmSeal(key, iv, pt []byte) ([]byte, error) {
	g, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return g.Seal(nil, iv, pt, nil), nil
}
func gcmOpen(key, iv, ct []byte) ([]byte, error) {
	g, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return g.Open(nil, iv, ct, nil)
}
func newGCM(key []byte) (cipher.AEAD, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(c)
}
func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	return b, err
}
