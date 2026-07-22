// crypto-gateway (Go) — frontera S3 del tier CLP: ÚNICO endpoint S3 del pipeline.
// PUT → cifra (sobre CLPE) / GET → descifra / HEAD,LIST,DELETE → passthrough. Servicio SEPARADO
// que reusa el esqueleto y el cliente S3 de gateway-go. Re-firma a Hetzner con el AWS SDK v2.
// NO valida SigV4 de sus clientes (confianza intra-cluster + NetworkPolicy).
package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
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
	s3  *S3
}

func main() {
	cfg := loadConfig()
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
	log.Fatal(http.ListenAndServe(":"+cfg.Port, mux))
}

// handle: enruta path-style /{bucket}/{key...}.
func (gw *Gateway) handle(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/")
	bucket, key := p, ""
	if i := strings.IndexByte(p, '/'); i >= 0 {
		bucket, key = p[:i], p[i+1:]
	}
	ctx := r.Context()
	switch r.Method {
	case http.MethodPut:
		gw.put(ctx, w, r, bucket, key)
	case http.MethodGet:
		if r.URL.Query().Get("list-type") == "2" {
			gw.list(ctx, w, r, bucket)
		} else {
			gw.get(ctx, w, bucket, key)
		}
	case http.MethodHead:
		gw.head(ctx, w, bucket, key)
	case http.MethodDelete:
		gw.del(ctx, w, bucket, key)
	default:
		s3err(w, 405, "MethodNotAllowed", "método no soportado")
	}
}

func (gw *Gateway) put(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket, key string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s3err(w, 400, "InvalidRequest", err.Error())
		return
	}
	etag := md5hex(body) // ETag = md5 del PLANTEXT recibido -> la validación del cliente cuadra
	meta := userMeta(r.Header)
	ct := r.Header.Get("Content-Type")
	if gw.cfg.encEnabled(key) {
		enc, err := Encrypt(body, tenantOf(key), KekFor)
		if err != nil {
			s3err(w, 500, "EncryptError", err.Error())
			return
		}
		body = enc
		meta["clp-enc"] = "CLPE1" // marca; el GET detecta por el magic igualmente
	}
	if err := gw.s3.Put(ctx, bucket, key, body, meta, ct, gw.cfg.ssec()); err != nil {
		s3err(w, 502, "UpstreamError", err.Error())
		return
	}
	w.Header().Set("ETag", `"`+etag+`"`)
	w.WriteHeader(200)
}

func (gw *Gateway) get(ctx context.Context, w http.ResponseWriter, bucket, key string) {
	body, meta, ct, err := gw.s3.Get(ctx, bucket, key, gw.cfg.ssec())
	if err != nil {
		gw.upstreamErr(w, err)
		return
	}
	if IsEnvelope(body) {
		pt, derr := Decrypt(body, KekFor)
		if derr != nil {
			s3err(w, 500, "DecryptError", derr.Error())
			return
		}
		body = pt
		delete(meta, "clp-enc")
	}
	if ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	for k, v := range meta {
		w.Header().Set("X-Amz-Meta-"+k, v)
	}
	w.Header().Set("ETag", `"`+md5hex(body)+`"`) // ETag del PLANTEXT devuelto (no del ciphertext)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(200)
	_, _ = w.Write(body)
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
	if v, e := strconv.Atoi(q.Get("max-keys")); e == nil {
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
			ETag: aws.ToString(o.ETag), Size: derefI64(o.Size), StorageClass: string(o.StorageClass)})
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
	s3err(w, 502, "UpstreamError", err.Error())
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
