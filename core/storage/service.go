package storage

import (
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// StorageService orchestrates file uploads, metadata persistence, and retrieval.
type StorageService struct {
	db      *gorm.DB
	cfg     *StorageConfig
	backend Storage
}

// New creates a StorageService with the configured backend.
func New(cfg *StorageConfig, db *gorm.DB) (*StorageService, error) {
	backend, err := NewStorage(cfg)
	if err != nil {
		return nil, fmt.Errorf("storage: init backend failed: %w", err)
	}
	return &StorageService{db: db, cfg: cfg, backend: backend}, nil
}

// Upload saves a file to the backend and records its metadata in the database.
func (s *StorageService) Upload(ctx context.Context, fh *multipart.FileHeader, uploaderID uint) (*File, error) {
	if fh.Size > s.cfg.MaxFileSize {
		return nil, fmt.Errorf("file size %d exceeds limit %d", fh.Size, s.cfg.MaxFileSize)
	}

	src, err := fh.Open()
	if err != nil {
		return nil, fmt.Errorf("storage: open upload failed: %w", err)
	}
	defer src.Close()

	ext := strings.ToLower(filepath.Ext(fh.Filename))
	storageName := uuid.New().String() + ext
	now := time.Now()
	key := fmt.Sprintf("%d/%02d/%02d/%s", now.Year(), now.Month(), now.Day(), storageName)

	path, err := s.backend.Save(ctx, key, src)
	if err != nil {
		return nil, err
	}

	mimeType := fh.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	record := &File{
		Filename:     storageName,
		OriginalName: fh.Filename,
		Size:         fh.Size,
		MimeType:     mimeType,
		StorageType:  s.cfg.Type,
		StoragePath:  path,
		UploaderID:   uploaderID,
	}

	if err := s.db.Create(record).Error; err != nil {
		// best-effort cleanup of backend file on DB failure
		_ = s.backend.Delete(ctx, path)
		return nil, fmt.Errorf("storage: save metadata failed: %w", err)
	}

	return record, nil
}

// List returns a paginated list of files.
func (s *StorageService) List(page, pageSize int) ([]File, int64, error) {
	var total int64
	if err := s.db.Model(&File{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var files []File
	offset := (page - 1) * pageSize
	if err := s.db.Order("id DESC").Offset(offset).Limit(pageSize).Find(&files).Error; err != nil {
		return nil, 0, err
	}

	return files, total, nil
}

// GetByID retrieves a single file record by ID.
func (s *StorageService) GetByID(id uint) (*File, error) {
	var f File
	if err := s.db.First(&f, id).Error; err != nil {
		return nil, err
	}
	return &f, nil
}

// OpenFile returns a readable stream of the file's content from the backend.
func (s *StorageService) OpenFile(ctx context.Context, f *File) (io.ReadCloser, error) {
	return s.backend.Open(ctx, f.StoragePath)
}

// Delete soft-deletes the file record (does not remove from backend).
func (s *StorageService) Delete(id uint) error {
	return s.db.Delete(&File{}, id).Error
}
