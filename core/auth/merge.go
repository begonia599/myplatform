package auth

import (
	"errors"
	"fmt"

	"gorm.io/gorm"
)

var (
	ErrMergeSelf          = errors.New("cannot merge a user into itself")
	ErrMergeRootInvolved  = errors.New("cannot merge root user")
	ErrMergeAlreadyMerged = errors.New("user is already merged")
	ErrMergeUserNotFound  = errors.New("user not found for merge")
)

// MergeUser merges the secondary user into the primary user atomically.
//
// All Casbin role assignments and core-internal foreign keys
// (oauth_accounts, images, files, refresh_tokens, user_profiles) are
// migrated. The secondary user is soft-deleted with merged_into set
// to the primary user's ID, and its username is renamed to free up the slot.
//
// Casbin operations execute outside the GORM transaction (the gorm-adapter
// uses its own writes). On Casbin failure the DB transaction is rolled back.
//
// Business apps with their own databases (e.g. blog) are not touched here.
// They should call Canonical(id) when looking up users by stale IDs.
func MergeUser(db *gorm.DB, perm PermissionApplier, primaryID, secondaryID uint) error {
	if primaryID == secondaryID {
		return ErrMergeSelf
	}

	// Pre-flight: load both users (must be active, not root, not already merged).
	var primary, secondary User
	if err := db.First(&primary, primaryID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("primary: %w", ErrMergeUserNotFound)
		}
		return fmt.Errorf("auth: load primary user: %w", err)
	}
	if err := db.First(&secondary, secondaryID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("secondary: %w", ErrMergeUserNotFound)
		}
		return fmt.Errorf("auth: load secondary user: %w", err)
	}
	if primary.IsRoot || secondary.IsRoot {
		return ErrMergeRootInvolved
	}
	if primary.MergedInto != nil || secondary.MergedInto != nil {
		return ErrMergeAlreadyMerged
	}

	// Run Casbin migration first; it has its own writes that aren't in the
	// gorm transaction. If Casbin fails, the DB stays untouched.
	if perm != nil {
		if err := perm.MigrateUserSubject(secondaryID, primaryID); err != nil {
			return fmt.Errorf("auth: migrate casbin subject: %w", err)
		}
	}

	// Run all DB updates in a single transaction.
	err := db.Transaction(func(tx *gorm.DB) error {
		// 1. oauth_accounts: move secondary's accounts to primary.
		// If primary already has an account for the same provider,
		// drop secondary's (primary wins).
		var secondaryOAuth []OAuthAccount
		if err := tx.Where("user_id = ?", secondaryID).Find(&secondaryOAuth).Error; err != nil {
			return fmt.Errorf("query secondary oauth: %w", err)
		}
		for _, acc := range secondaryOAuth {
			var existing OAuthAccount
			err := tx.Where("user_id = ? AND provider = ?", primaryID, acc.Provider).
				First(&existing).Error
			if err == nil {
				// Conflict: primary already has this provider.
				if err := tx.Delete(&OAuthAccount{}, acc.ID).Error; err != nil {
					return fmt.Errorf("drop conflicting oauth: %w", err)
				}
				continue
			}
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("check primary oauth: %w", err)
			}
			if err := tx.Model(&OAuthAccount{}).Where("id = ?", acc.ID).
				Update("user_id", primaryID).Error; err != nil {
				return fmt.Errorf("move oauth account: %w", err)
			}
		}

		// 2. imagebed.images.uploader_id (raw SQL — table belongs to another package).
		if err := tx.Exec(
			"UPDATE images SET uploader_id = ? WHERE uploader_id = ?",
			primaryID, secondaryID,
		).Error; err != nil {
			return fmt.Errorf("migrate images: %w", err)
		}

		// 3. storage.files.uploader_id.
		if err := tx.Exec(
			"UPDATE files SET uploader_id = ? WHERE uploader_id = ?",
			primaryID, secondaryID,
		).Error; err != nil {
			return fmt.Errorf("migrate files: %w", err)
		}

		// 4. user_profiles: secondary's profile is dropped (primary keeps its own).
		if err := tx.Where("user_id = ?", secondaryID).Delete(&UserProfile{}).Error; err != nil {
			return fmt.Errorf("delete secondary profile: %w", err)
		}

		// 5. refresh_tokens: revoke all secondary tokens (force re-login).
		if err := tx.Model(&RefreshToken{}).
			Where("user_id = ? AND revoked = ?", secondaryID, false).
			Update("revoked", true).Error; err != nil {
			return fmt.Errorf("revoke secondary tokens: %w", err)
		}

		// 6. users: rename + set merged_into + soft delete.
		newUsername := fmt.Sprintf("%s_merged_%d", secondary.Username, secondary.ID)
		if err := tx.Model(&User{}).Where("id = ?", secondaryID).
			Updates(map[string]any{
				"username":    newUsername,
				"merged_into": primaryID,
				"status":      "merged",
			}).Error; err != nil {
			return fmt.Errorf("rename secondary: %w", err)
		}
		if err := tx.Delete(&User{}, secondaryID).Error; err != nil {
			return fmt.Errorf("soft-delete secondary: %w", err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("auth: merge user %d into %d: %w", secondaryID, primaryID, err)
	}
	return nil
}

// Canonical resolves a user ID through the merged_into chain and returns
// the canonical (still-active) user ID. If the user is not merged or
// not found, the original ID is returned.
//
// Cycle detection limits chain depth to 16 hops.
func (s *AuthService) Canonical(id uint) uint {
	current := id
	for i := 0; i < 16; i++ {
		var u User
		// Use Unscoped to follow soft-deleted (merged) users.
		if err := s.db.Unscoped().Select("id", "merged_into").First(&u, current).Error; err != nil {
			return current
		}
		if u.MergedInto == nil {
			return u.ID
		}
		current = *u.MergedInto
	}
	return current
}

// GetCanonicalUserByID returns the active user that the given ID resolves to,
// following any merged_into chain. Returns ErrInvalidCredentials if the
// final canonical user is not active.
func (s *AuthService) GetCanonicalUserByID(id uint) (*User, error) {
	canonicalID := s.Canonical(id)
	return s.GetUserByID(canonicalID)
}

// PurgeMergedUser permanently removes a tombstone (a user that has been
// merged into another). The caller must be either an admin/root or the
// canonical user (the merge target). All remaining auxiliary rows
// (refresh_tokens, profile leftovers) are also hard-deleted.
//
// Returns ErrMergeUserNotFound if the user does not exist;
// errors.New("user is not merged") if the user has no merged_into;
// errors.New("forbidden") if callerID is neither admin nor the merge target.
func (s *AuthService) PurgeMergedUser(callerID, targetID uint) error {
	var caller User
	if err := s.db.First(&caller, callerID).Error; err != nil {
		return fmt.Errorf("auth: load caller: %w", err)
	}

	var target User
	// Use Unscoped to find soft-deleted tombstones.
	if err := s.db.Unscoped().First(&target, targetID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrMergeUserNotFound
		}
		return fmt.Errorf("auth: load target: %w", err)
	}
	if target.MergedInto == nil {
		return errors.New("user is not merged")
	}
	if !caller.IsRoot && caller.Role != "admin" && *target.MergedInto != callerID {
		return errors.New("forbidden")
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		// Drop any remaining child rows that referenced the tombstone.
		if err := tx.Unscoped().Where("user_id = ?", targetID).Delete(&UserProfile{}).Error; err != nil {
			return fmt.Errorf("delete profile: %w", err)
		}
		if err := tx.Unscoped().Where("user_id = ?", targetID).Delete(&RefreshToken{}).Error; err != nil {
			return fmt.Errorf("delete refresh tokens: %w", err)
		}
		if err := tx.Unscoped().Where("user_id = ?", targetID).Delete(&OAuthAccount{}).Error; err != nil {
			return fmt.Errorf("delete oauth accounts: %w", err)
		}
		// Hard-delete the user row itself.
		if err := tx.Unscoped().Delete(&User{}, targetID).Error; err != nil {
			return fmt.Errorf("delete user: %w", err)
		}
		return nil
	})
}
