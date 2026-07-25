// crypto-gateway (Go) — frontera S3 del tier CLP: ÚNICO endpoint S3 del pipeline.
// PUT → cifra (sobre CLPE) / GET → descifra / HEAD,LIST,DELETE → passthrough. Servicio SEPARADO
// que reusa el esqueleto y el cliente S3 de gateway-go. Re-firma a Hetzner con el AWS SDK v2.
// NO valida SigV4 de sus clientes (confianza intra-cluster + NetworkPolicy).
package main

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/guigra/s3-crypto-gateway/pkg/clpe"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

type Gateway struct {
	cfg Config
	s3  s3Backend
}

type s3Backend interface {
	Get(context.Context, string, string, *SSEC, int64) ([]byte, map[string]string, string, error)
	Put(context.Context, string, string, []byte, map[string]string, string, *SSEC) error
	Head(context.Context, string, string, *SSEC) (*s3.HeadObjectOutput, error)
	Delete(context.Context, string, string) error
	List(context.Context, string, string, string, string, int32) (*s3.ListObjectsV2Output, error)
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("configuración inválida: %v", err)
	}
	backend, err := newS3()
	if err != nil {
		log.Fatalf("no se pudo crear el cliente S3: %v", err)
	}
	gw := &Gateway{cfg: cfg, s3: backend}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/", gw.handle)

	log.Printf("crypto-gateway :%s  encrypt=%v tenants=%v prefixes=%v  endpoint=%s",
		cfg.Port, cfg.EncEnabled, cfg.EncTenants, cfg.EncPrefixes, env("AWS_ENDPOINT_URL", ""))
	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           mux,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}
	log.Fatal(server.ListenAndServe())
}

// handle: enruta path-style /{bucket}/{key...}.
func (gw *Gateway) handle(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/")
	bucket, key := p, ""
	if i := strings.IndexByte(p, '/'); i >= 0 {
		bucket, key = p[:i], p[i+1:]
	}
	if bucket == "" {
		s3err(w, http.StatusBadRequest, "InvalidURI", "la ruta debe incluir un bucket")
		return
	}
	if feature := unsupportedFeature(r, key); feature != "" {
		s3err(w, http.StatusNotImplemented, "NotImplemented", "función S3 no soportada: "+feature)
		return
	}
	ctx := r.Context()
	switch r.Method {
	case http.MethodPut:
		gw.put(ctx, w, r, bucket, key)
	case http.MethodGet:
		if r.URL.Query().Get("list-type") == "2" {
			gw.list(ctx, w, r, bucket)
		} else {
			gw.get(ctx, w, r, bucket, key)
		}
	case http.MethodHead:
		gw.head(ctx, w, bucket, key)
	case http.MethodDelete:
		gw.del(ctx, w, bucket, key)
	case http.MethodPost:
		s3err(w, http.StatusNotImplemented, "NotImplemented", "las operaciones S3 mediante POST no están soportadas")
	default:
		s3err(w, 405, "MethodNotAllowed", "método no soportado")
	}
}

func unsupportedFeature(r *http.Request, key string) string {
	if key == "" {
		if r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2" {
			// ListObjectsV2 is the only supported bucket-level operation.
		} else {
			return "operación a nivel de bucket"
		}
	}

	for _, header := range []string{
		"If-Modified-Since",
		"If-Unmodified-Since",
		"If-Range",
		"X-Amz-Copy-Source",
		"X-Amz-Checksum-Mode",
		"Content-Encoding",
		"Content-Disposition",
		"Cache-Control",
		"Expires",
	} {
		if r.Header.Get(header) != "" {
			return "cabecera " + header
		}
	}
	if r.Header.Get("Range") != "" && (r.Method != http.MethodGet || key == "") {
		return "cabecera Range fuera de GetObject"
	}
	if r.Header.Get("Content-MD5") != "" && (r.Method != http.MethodPut || key == "") {
		return "cabecera Content-MD5 fuera de PutObject"
	}
	if algorithm := rfcChecksumAlgorithm(r.Header.Get("X-Amz-Sdk-Checksum-Algorithm")); algorithm != "" {
		if r.Method != http.MethodPut || key == "" || algorithm != "SHA256" {
			return "algoritmo de checksum " + algorithm
		}
	}
	for header := range r.Header {
		lowerHeader := strings.ToLower(header)
		if strings.HasPrefix(lowerHeader, "x-amz-checksum-") {
			if lowerHeader == "x-amz-checksum-sha256" && r.Method == http.MethodPut && key != "" {
				continue
			}
			return "checksums S3"
		}
		for _, unsupportedPrefix := range []string{
			"x-amz-acl",
			"x-amz-grant-",
			"x-amz-object-lock-",
			"x-amz-server-side-encryption",
			"x-amz-storage-class",
			"x-amz-tagging",
			"x-amz-website-redirect-location",
			"x-amz-request-payer",
			"x-amz-expected-bucket-owner",
		} {
			if strings.HasPrefix(lowerHeader, unsupportedPrefix) {
				return "cabecera " + header
			}
		}
	}

	supportedListQuery := map[string]bool{
		"list-type":          true,
		"prefix":             true,
		"continuation-token": true,
		"delimiter":          true,
		"max-keys":           true,
	}
	for query := range r.URL.Query() {
		if key == "" && r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2" && supportedListQuery[query] {
			continue
		}
		return "parámetro " + query
	}
	return ""
}

func (gw *Gateway) put(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket, key string) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, gw.cfg.MaxObjectBytes))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			s3err(w, http.StatusRequestEntityTooLarge, "EntityTooLarge", "el objeto supera el tamaño máximo permitido")
			return
		}
		internalErr(w, 400, "InvalidRequest", "no se pudo leer el cuerpo de la petición", err)
		return
	}
	if err := validatePutChecksums(r.Header, body); err != nil {
		s3err(w, http.StatusBadRequest, "BadDigest", err.Error())
		return
	}
	etag := md5hex(body) // ETag = md5 del PLANTEXT recibido -> la validación del cliente cuadra
	meta := userMeta(r.Header)
	ct := r.Header.Get("Content-Type")
	if gw.cfg.encEnabled(key) {
		enc, err := clpe.Encrypt(body, tenantOf(key), key, KekFor)
		if err != nil {
			internalErr(w, 500, "EncryptError", "no se pudo cifrar el objeto", err)
			return
		}
		body = enc
		meta["clp-enc"] = "CLPE2" // marca; el GET detecta por el magic igualmente
	}
	if err := gw.s3.Put(ctx, bucket, key, body, meta, ct, gw.cfg.ssec()); err != nil {
		internalErr(w, 502, "UpstreamError", "el backend S3 no pudo completar la operación", err)
		return
	}
	w.Header().Set("ETag", `"`+etag+`"`)
	w.WriteHeader(200)
}

func (gw *Gateway) get(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket, key string) {
	maxBackendBytes := gw.cfg.MaxObjectBytes + clpe.MaxEnvelopeOverhead
	body, meta, ct, err := gw.s3.Get(ctx, bucket, key, gw.cfg.ssec(), maxBackendBytes)
	if err != nil {
		gw.upstreamErr(w, err)
		return
	}
	if clpe.IsEnvelope(body) {
		if tenantErr := validateEnvelopeTenant(body, key); tenantErr != nil {
			internalErr(w, 500, "DecryptError", "no se pudo descifrar el objeto", tenantErr)
			return
		}
		pt, derr := clpe.Decrypt(body, key, KekFor)
		if derr != nil {
			internalErr(w, 500, "DecryptError", "no se pudo descifrar el objeto", derr)
			return
		}
		body = pt
		delete(meta, "clp-enc")
	}
	if int64(len(body)) > gw.cfg.MaxObjectBytes {
		s3err(w, http.StatusRequestEntityTooLarge, "EntityTooLarge", "el objeto supera el tamaño máximo permitido")
		return
	}
	etag := md5hex(body)
	if ifMatch := r.Header.Get("If-Match"); ifMatch != "" && !etagMatches(ifMatch, etag, false) {
		s3err(w, http.StatusPreconditionFailed, "PreconditionFailed", "la condición If-Match no se cumple")
		return
	}
	if ifNoneMatch := r.Header.Get("If-None-Match"); ifNoneMatch != "" && etagMatches(ifNoneMatch, etag, true) {
		w.Header().Set("ETag", `"`+etag+`"`)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	status := http.StatusOK
	if rangeHeader := r.Header.Get("Range"); rangeHeader != "" {
		fullSize := int64(len(body))
		start, end, rangeErr := parseByteRange(rangeHeader, fullSize)
		if rangeErr != nil {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", len(body)))
			s3err(w, http.StatusRequestedRangeNotSatisfiable, "InvalidRange", "el rango solicitado no es válido")
			return
		}
		body = body[start : end+1]
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, fullSize))
		w.Header().Set("Accept-Ranges", "bytes")
		status = http.StatusPartialContent
	}
	if ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	for k, v := range meta {
		w.Header().Set("X-Amz-Meta-"+k, v)
	}
	w.Header().Set("ETag", `"`+etag+`"`) // ETag del PLANTEXT devuelto (no del ciphertext)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func validatePutChecksums(header http.Header, body []byte) error {
	if value := header.Get("Content-MD5"); value != "" {
		expected, err := base64.StdEncoding.DecodeString(value)
		sum := md5.Sum(body)
		if err != nil || len(expected) != len(sum) || subtle.ConstantTimeCompare(expected, sum[:]) != 1 {
			return errors.New("Content-MD5 no coincide con el cuerpo recibido")
		}
	}
	if value := header.Get("X-Amz-Checksum-Sha256"); value != "" {
		expected, err := base64.StdEncoding.DecodeString(value)
		sum := sha256.Sum256(body)
		if err != nil || len(expected) != len(sum) || subtle.ConstantTimeCompare(expected, sum[:]) != 1 {
			return errors.New("X-Amz-Checksum-Sha256 no coincide con el cuerpo recibido")
		}
	}
	if algorithm := rfcChecksumAlgorithm(header.Get("X-Amz-Sdk-Checksum-Algorithm")); algorithm != "" {
		if algorithm != "SHA256" || header.Get("X-Amz-Checksum-Sha256") == "" {
			return errors.New("el checksum solicitado requiere una cabecera SHA-256 explícita")
		}
	}
	return nil
}

func rfcChecksumAlgorithm(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}

func etagMatches(condition, etag string, weakComparison bool) bool {
	for _, candidate := range strings.Split(condition, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" {
			return true
		}
		weak := strings.HasPrefix(candidate, "W/")
		if weak {
			candidate = strings.TrimSpace(strings.TrimPrefix(candidate, "W/"))
		}
		if weak && !weakComparison {
			continue
		}
		if candidate == `"`+etag+`"` {
			return true
		}
	}
	return false
}

func parseByteRange(value string, size int64) (int64, int64, error) {
	if size <= 0 || !strings.HasPrefix(value, "bytes=") {
		return 0, 0, errors.New("formato Range inválido")
	}
	spec := strings.TrimPrefix(value, "bytes=")
	if strings.Contains(spec, ",") {
		return 0, 0, errors.New("múltiples rangos no soportados")
	}
	startText, endText, ok := strings.Cut(spec, "-")
	if !ok || (startText == "" && endText == "") {
		return 0, 0, errors.New("rango vacío")
	}
	if startText == "" {
		suffix, err := strconv.ParseInt(endText, 10, 64)
		if err != nil || suffix <= 0 {
			return 0, 0, errors.New("sufijo Range inválido")
		}
		if suffix > size {
			suffix = size
		}
		return size - suffix, size - 1, nil
	}
	start, err := strconv.ParseInt(startText, 10, 64)
	if err != nil || start < 0 || start >= size {
		return 0, 0, errors.New("inicio Range inválido")
	}
	if endText == "" {
		return start, size - 1, nil
	}
	end, err := strconv.ParseInt(endText, 10, 64)
	if err != nil || end < start {
		return 0, 0, errors.New("fin Range inválido")
	}
	if end >= size {
		end = size - 1
	}
	return start, end, nil
}

func (gw *Gateway) head(ctx context.Context, w http.ResponseWriter, bucket, key string) {
	out, err := gw.s3.Head(ctx, bucket, key, gw.cfg.ssec())
	if err != nil {
		gw.upstreamErr(w, err)
		return
	}
	// Nota F1: Content-Length = tamaño del CIPHERTEXT (Hetzner). El GET devuelve plano (otro tamaño).
	if out.ContentLength != nil {
		w.Header().Set("Content-Length", strconv.FormatInt(*out.ContentLength, 10))
	}
	for k, v := range out.Metadata {
		w.Header().Set("X-Amz-Meta-"+k, v)
	}
	if out.ETag != nil {
		w.Header().Set("ETag", *out.ETag)
	}
	w.WriteHeader(200)
}

func (gw *Gateway) del(ctx context.Context, w http.ResponseWriter, bucket, key string) {
	if err := gw.s3.Delete(ctx, bucket, key); err != nil {
		gw.upstreamErr(w, err)
		return
	}
	w.WriteHeader(204)
}

// list: ListObjectsV2 → XML S3 (metadata de ruta en claro → prefiltrado §7 intacto).
func (gw *Gateway) list(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string) {
	q := r.URL.Query()
	maxKeys := int32(0)
	// ParseInt con bitSize 32: rechaza valores fuera de rango int32 (el Atoi previo
	// permitía overflow con un max-keys hostil — hallazgo de CodeQL).
	if v, e := strconv.ParseInt(q.Get("max-keys"), 10, 32); e == nil && v > 0 {
		maxKeys = int32(v)
	}
	out, err := gw.s3.List(ctx, bucket, q.Get("prefix"), q.Get("continuation-token"), q.Get("delimiter"), maxKeys)
	if err != nil {
		gw.upstreamErr(w, err)
		return
	}
	res := listResult{Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/", Name: bucket,
		Prefix: q.Get("prefix"), Delimiter: q.Get("delimiter"), MaxKeys: derefI32(out.MaxKeys),
		KeyCount: derefI32(out.KeyCount), IsTruncated: derefBool(out.IsTruncated),
		NextContinuationToken: aws.ToString(out.NextContinuationToken)}
	for _, o := range out.Contents {
		res.Contents = append(res.Contents, listObj{Key: aws.ToString(o.Key),
			LastModified: o.LastModified.UTC().Format("2006-01-02T15:04:05.000Z"),
			ETag:         aws.ToString(o.ETag), Size: derefI64(o.Size), StorageClass: string(o.StorageClass)})
	}
	for _, cp := range out.CommonPrefixes {
		res.CommonPrefixes = append(res.CommonPrefixes, commonPrefix{Prefix: aws.ToString(cp.Prefix)})
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(200)
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(res)
}

// upstreamErr: traduce errores del SDK (NoSuchKey → 404) a respuestas S3.
func (gw *Gateway) upstreamErr(w http.ResponseWriter, err error) {
	var nsk *s3types.NoSuchKey
	var nf *s3types.NotFound
	if errors.As(err, &nsk) || errors.As(err, &nf) {
		s3err(w, 404, "NoSuchKey", "objeto no encontrado")
		return
	}
	if errors.Is(err, ErrObjectTooLarge) {
		s3err(w, http.StatusRequestEntityTooLarge, "EntityTooLarge", "el objeto supera el tamaño máximo permitido")
		return
	}
	internalErr(w, 502, "UpstreamError", "el backend S3 no pudo completar la operación", err)
}

// --- XML ---
type listResult struct {
	XMLName               xml.Name       `xml:"ListBucketResult"`
	Xmlns                 string         `xml:"xmlns,attr"`
	Name                  string         `xml:"Name"`
	Prefix                string         `xml:"Prefix"`
	Delimiter             string         `xml:"Delimiter,omitempty"`
	KeyCount              int32          `xml:"KeyCount"`
	MaxKeys               int32          `xml:"MaxKeys"`
	IsTruncated           bool           `xml:"IsTruncated"`
	NextContinuationToken string         `xml:"NextContinuationToken,omitempty"`
	Contents              []listObj      `xml:"Contents"`
	CommonPrefixes        []commonPrefix `xml:"CommonPrefixes"`
}
type listObj struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}
type commonPrefix struct {
	Prefix string `xml:"Prefix"`
}
type s3errBody struct {
	XMLName xml.Name `xml:"Error"`
	Code    string   `xml:"Code"`
	Message string   `xml:"Message"`
}

func s3err(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(s3errBody{Code: code, Message: msg})
}

func internalErr(w http.ResponseWriter, status int, code, publicMessage string, err error) {
	requestID := requestID()
	log.Printf("request_id=%s code=%s error=%v", requestID, code, err)
	w.Header().Set("X-Amz-Request-Id", requestID)
	s3err(w, status, code, publicMessage)
}

func requestID() string {
	var id [8]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return "unavailable"
	}
	return hex.EncodeToString(id[:])
}

func validateEnvelopeTenant(envelope []byte, key string) error {
	envelopeTenant, err := clpe.Tenant(envelope)
	if err != nil {
		return err
	}
	routeTenant := tenantOf(key)
	if envelopeTenant != routeTenant {
		return fmt.Errorf("tenant del sobre %q no coincide con tenant de ruta %q", envelopeTenant, routeTenant)
	}
	return nil
}

// userMeta: cabeceras X-Amz-Meta-<k> -> map (clave en minúsculas, sin el prefijo).
func userMeta(h http.Header) map[string]string {
	m := map[string]string{}
	for k, v := range h {
		if lk := strings.ToLower(k); strings.HasPrefix(lk, "x-amz-meta-") && len(v) > 0 {
			m[strings.TrimPrefix(lk, "x-amz-meta-")] = v[0]
		}
	}
	return m
}

func md5hex(b []byte) string { s := md5.Sum(b); return hex.EncodeToString(s[:]) }
func derefI32(p *int32) int32 {
	if p != nil {
		return *p
	}
	return 0
}
func derefI64(p *int64) int64 {
	if p != nil {
		return *p
	}
	return 0
}
func derefBool(p *bool) bool { return p != nil && *p }
