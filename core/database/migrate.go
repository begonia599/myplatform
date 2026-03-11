package database

import "gorm.io/gorm"

// AutoMigrate runs GORM's AutoMigrate for the given model structs.
func AutoMigrate(db *gorm.DB, models ...any) error {
	return db.AutoMigrate(models...)
}
