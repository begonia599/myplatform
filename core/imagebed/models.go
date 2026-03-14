package imagebed

import (
	"time"

	"gorm.io/gorm"
)

// Image represents an uploaded image's metadata stored in PostgreSQL.
type Image struct {
	ID           uint           `gorm:"primaryKey" json:"id"`
	Filename     string         `gorm:"size:255;not null" json:"filename"`
	OriginalName string         `gorm:"size:255;not null" json:"original_name"`
	Size         int64          `gorm:"not null" json:"size"`
	MimeType     string         `gorm:"size:127;not null" json:"mime_type"`
	StoragePath  string         `gorm:"size:512;not null" json:"storage_path"`
	UploaderID   uint           `gorm:"index;not null" json:"uploader_id"`
	IsPublic     bool           `gorm:"default:true" json:"is_public"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}
