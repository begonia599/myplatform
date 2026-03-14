package imagebed

import (
	"context"
	"fmt"
	"mime/multipart"
	"path/filepath"
	"strings"
	"time"

	"github.com/begonia599/myplatform/core/storage"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// allowedImageTypes lists accepted image MIME types.
var allowedImageTypes = map[string]bool{
	"image/jpeg":    true,
	"image/png":     true,
	"image/gif":     true,
	"image/webp":    true,
	"image/svg+xml": true,
	"image/bmp":     true,
	"image/x-icon":  true,
}

// ImageBedService orchestrates image uploads, metadata persistence, and retrieval.
type ImageBedService struct {
	db       *gorm.DB
	cfg      *ImageBedConfig
	backend  storage.Storage
	basePath string
}

// New creates an ImageBedService that reuses the storage backend.
func New(cfg *ImageBedConfig, storageCfg *storage.StorageConfig, db *gorm.DB) (*ImageBedService, error) {
	backend, err := storage.NewStorage(storageCfg)
	if err != nil {
		return nil, fmt.Errorf("imagebed: init storage backend failed: %w", err)
	}
	return &ImageBedService{db: db, cfg: cfg, backend: backend, basePath: cfg.BasePath}, nil
}

// Upload saves an image to the backend and records its metadata.
func (s *ImageBedService) Upload(ctx context.Context, fh *multipart.FileHeader, uploaderID uint) (*Image, error) {
	// Validate size
	if fh.Size > s.cfg.MaxFileSize {
		return nil, fmt.Errorf("file size %d exceeds limit %d", fh.Size, s.cfg.MaxFileSize)
	}

	// Validate MIME type
	mimeType := fh.Header.Get("Content-Type")
	if !allowedImageTypes[mimeType] {
		return nil, fmt.Errorf("unsupported image type: %s", mimeType)
	}

	src, err := fh.Open()
	if err != nil {
		return nil, fmt.Errorf("imagebed: open upload failed: %w", err)
	}
	defer src.Close()

	ext := strings.ToLower(filepath.Ext(fh.Filename))
	storageName := uuid.New().String() + ext
	now := time.Now()
	key := fmt.Sprintf("%s/%d/%02d/%02d/%s", s.basePath, now.Year(), now.Month(), now.Day(), storageName)

	path, err := s.backend.Save(ctx, key, src)
	if err != nil {
		return nil, err
	}

	record := &Image{
		Filename:     storageName,
		OriginalName: fh.Filename,
		Size:         fh.Size,
		MimeType:     mimeType,
		StoragePath:  path,
		UploaderID:   uploaderID,
		IsPublic:     true,
	}

	if err := s.db.Create(record).Error; err != nil {
		_ = s.backend.Delete(ctx, path)
		return nil, fmt.Errorf("imagebed: save metadata failed: %w", err)
	}

	return record, nil
}

// ListByUser returns a paginated list of images for a specific user.
func (s *ImageBedService) ListByUser(userID uint, page, pageSize int) ([]Image, int64, error) {
	var total int64
	query := s.db.Model(&Image{}).Where("uploader_id = ?", userID)
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var images []Image
	offset := (page - 1) * pageSize
	if err := query.Order("id DESC").Offset(offset).Limit(pageSize).Find(&images).Error; err != nil {
		return nil, 0, err
	}

	return images, total, nil
}

// GetByID retrieves a single image record by ID.
func (s *ImageBedService) GetByID(id uint) (*Image, error) {
	var img Image
	if err := s.db.First(&img, id).Error; err != nil {
		return nil, err
	}
	return &img, nil
}

// OpenImage returns a readable stream of the image content from the backend.
func (s *ImageBedService) OpenImage(ctx context.Context, img *Image) (interface{ Read([]byte) (int, error); Close() error }, error) {
	return s.backend.Open(ctx, img.StoragePath)
}

// Delete removes an image. Owner or admin can delete.
func (s *ImageBedService) Delete(ctx context.Context, id, userID uint, role string) error {
	img, err := s.GetByID(id)
	if err != nil {
		return err
	}

	if img.UploaderID != userID && role != "admin" {
		return fmt.Errorf("permission denied")
	}

	// Delete from storage backend
	_ = s.backend.Delete(ctx, img.StoragePath)

	return s.db.Delete(&Image{}, id).Error
}

// ToggleVisibility changes the public/private status of an image.
func (s *ImageBedService) ToggleVisibility(id, userID uint, role string, isPublic bool) (*Image, error) {
	img, err := s.GetByID(id)
	if err != nil {
		return nil, err
	}

	if img.UploaderID != userID && role != "admin" {
		return nil, fmt.Errorf("permission denied")
	}

	img.IsPublic = isPublic
	if err := s.db.Save(img).Error; err != nil {
		return nil, err
	}

	return img, nil
}
