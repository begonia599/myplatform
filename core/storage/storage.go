package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Storage is the pluggable backend interface for file persistence.
type Storage interface {
	Save(ctx context.Context, key string, reader io.Reader) (string, error)
	Open(ctx context.Context, path string) (io.ReadCloser, error)
	Delete(ctx context.Context, path string) error
}

// NewStorage creates a Storage backend based on the config type.
func NewStorage(cfg *StorageConfig) (Storage, error) {
	switch cfg.Type {
	case "local":
		return NewLocalStorage(cfg.Local.BasePath)
	case "s3":
		return NewS3Storage(&cfg.S3)
	default:
		return nil, fmt.Errorf("storage: unsupported type %q", cfg.Type)
	}
}

// --- LocalStorage ---

// LocalStorage stores files on the local filesystem.
type LocalStorage struct {
	basePath string
}

// NewLocalStorage creates a LocalStorage rooted at basePath.
func NewLocalStorage(basePath string) (*LocalStorage, error) {
	if err := os.MkdirAll(basePath, 0o755); err != nil {
		return nil, fmt.Errorf("storage: failed to create base path %q: %w", basePath, err)
	}
	return &LocalStorage{basePath: basePath}, nil
}

func (l *LocalStorage) Save(_ context.Context, key string, reader io.Reader) (string, error) {
	fullPath := filepath.Join(l.basePath, key)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		return "", fmt.Errorf("storage: mkdir failed: %w", err)
	}

	f, err := os.Create(fullPath)
	if err != nil {
		return "", fmt.Errorf("storage: create file failed: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, reader); err != nil {
		return "", fmt.Errorf("storage: write failed: %w", err)
	}
	return key, nil
}

func (l *LocalStorage) Open(_ context.Context, path string) (io.ReadCloser, error) {
	fullPath := filepath.Join(l.basePath, path)
	f, err := os.Open(fullPath)
	if err != nil {
		return nil, fmt.Errorf("storage: open file failed: %w", err)
	}
	return f, nil
}

func (l *LocalStorage) Delete(_ context.Context, path string) error {
	fullPath := filepath.Join(l.basePath, path)
	if err := os.Remove(fullPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("storage: delete failed: %w", err)
	}
	return nil
}

// --- S3Storage ---

// S3Storage stores files in an S3-compatible bucket.
type S3Storage struct {
	client *s3.Client
	bucket string
}

// NewS3Storage creates an S3Storage client from configuration.
func NewS3Storage(cfg *S3Config) (*S3Storage, error) {
	opts := []func(*s3.Options){
		func(o *s3.Options) {
			o.Region = cfg.Region
			o.Credentials = credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, "")
			o.UsePathStyle = true // required for MinIO and many S3-compatible services
		},
	}

	if cfg.Endpoint != "" {
		scheme := "https"
		if !cfg.UseSSL {
			scheme = "http"
		}
		endpoint := fmt.Sprintf("%s://%s", scheme, cfg.Endpoint)
		opts = append(opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(endpoint)
		})
	}

	client := s3.New(s3.Options{}, opts...)

	return &S3Storage{client: client, bucket: cfg.Bucket}, nil
}

func (s *S3Storage) Save(ctx context.Context, key string, reader io.Reader) (string, error) {
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
		Body:   reader,
	})
	if err != nil {
		return "", fmt.Errorf("storage: s3 put failed: %w", err)
	}
	return key, nil
}

func (s *S3Storage) Open(ctx context.Context, path string) (io.ReadCloser, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(path),
	})
	if err != nil {
		return nil, fmt.Errorf("storage: s3 get failed: %w", err)
	}
	return out.Body, nil
}

func (s *S3Storage) Delete(ctx context.Context, path string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(path),
	})
	if err != nil {
		return fmt.Errorf("storage: s3 delete failed: %w", err)
	}
	return nil
}
