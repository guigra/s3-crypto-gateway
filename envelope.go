package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

// Sobre CLPE — MISMO formato byte-a-byte que el Encryptor Java del appender, para
// que ambas implementaciones sean interoperables:
//
//	magic(4)="CLPE" | ver(1)=1 | tenantLen(1)|tenant | ivDek(12) | dekCtLen(2 BE)|dekCt
//	| ivData(12) | dataCt(resto)
//
// Cifrado de SOBRE AES-256-GCM: DEK aleatoria por objeto (32B) cifra el dato; la DEK se envuelve
// con la KEK del tenant. GCM autentica -> cualquier manipulación falla al descifrar.
var clpeMagic = []byte("CLPE")

const (
	clpeVersion = 1
	ivLen       = 12 // nonce GCM
	dekLen      = 32 // AES-256
)

// KekFn devuelve la KEK (32 bytes) de un tenant.
type KekFn func(tenant string) ([]byte, error)

// IsEnvelope: true si b empieza por el magic CLPE (para decidir descifrar en GET).
func IsEnvelope(b []byte) bool { return len(b) >= 4 && string(b[:4]) == "CLPE" }

// Encrypt produce el sobre CLPE de pt bajo la KEK del tenant.
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

// Decrypt descifra un sobre CLPE. Falla si está manipulado o la KEK es errónea.
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
