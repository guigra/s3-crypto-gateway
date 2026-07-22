package main

import (
	"bytes"
	"context"
	"io"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3 es el backend a Hetzner — MISMO cliente que gateway-go (BaseEndpoint + UsePathStyle + creds
// del SDK por env: AWS_ENDPOINT_URL/AWS_REGION/AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY).
type S3 struct{ c *s3.Client }

func newS3() (*S3, error) {
	cfg, err := awscfg.LoadDefaultConfig(context.Background(),
		awscfg.WithRegion(env("AWS_REGION", "us-east-1")))
	if err != nil {
		return nil, err
	}
	endpoint := os.Getenv("AWS_ENDPOINT_URL")
	c := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
		o.UsePathStyle = true // endpoint S3 custom (Hetzner)
	})
	return &S3{c: c}, nil
}

// Get devuelve cuerpo + metadata de usuario + content-type del objeto.
func (b *S3) Get(ctx context.Context, bucket, key string, sse *SSEC) ([]byte, map[string]string, string, error) {
	in := &s3.GetObjectInput{Bucket: &bucket, Key: &key}
	if sse != nil {
		in.SSECustomerAlgorithm, in.SSECustomerKey, in.SSECustomerKeyMD5 = &sse.Algorithm, &sse.KeyB64, &sse.KeyMD5B64
	}
	out, err := b.c.GetObject(ctx, in)
	if err != nil {
		return nil, nil, "", err
	}
	defer out.Body.Close()
	body, err := io.ReadAll(out.Body)
	ct := ""
	if out.ContentType != nil {
		ct = *out.ContentType
	}
	return body, out.Metadata, ct, err
}

// Put sube body con metadata de usuario (y content-type opcional). SSE-C opcional (capa extra).
func (b *S3) Put(ctx context.Context, bucket, key string, body []byte, meta map[string]string, contentType string, sse *SSEC) error {
	in := &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: bytes.NewReader(body), Metadata: meta}
	if contentType != "" {
		in.ContentType = &contentType
	}
	if sse != nil {
		in.SSECustomerAlgorithm, in.SSECustomerKey, in.SSECustomerKeyMD5 = &sse.Algorithm, &sse.KeyB64, &sse.KeyMD5B64
	}
	_, err := b.c.PutObject(ctx, in)
	return err
}

func (b *S3) Head(ctx context.Context, bucket, key string, sse *SSEC) (*s3.HeadObjectOutput, error) {
	in := &s3.HeadObjectInput{Bucket: &bucket, Key: &key}
	if sse != nil {
		in.SSECustomerAlgorithm, in.SSECustomerKey, in.SSECustomerKeyMD5 = &sse.Algorithm, &sse.KeyB64, &sse.KeyMD5B64
	}
	return b.c.HeadObject(ctx, in)
}

func (b *S3) Delete(ctx context.Context, bucket, key string) error {
	_, err := b.c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &key})
	return err
}

// List ejecuta ListObjectsV2 (passthrough; la metadata de ruta queda en claro → prefiltrado §7).
func (b *S3) List(ctx context.Context, bucket, prefix, token, delimiter string, maxKeys int32) (*s3.ListObjectsV2Output, error) {
	in := &s3.ListObjectsV2Input{Bucket: &bucket}
	if prefix != "" {
		in.Prefix = &prefix
	}
	if token != "" {
		in.ContinuationToken = &token
	}
	if delimiter != "" {
		in.Delimiter = &delimiter
	}
	if maxKeys > 0 {
		in.MaxKeys = aws.Int32(maxKeys)
	}
	return b.c.ListObjectsV2(ctx, in)
}
