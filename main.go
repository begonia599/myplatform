package main

import (
	"fmt"
	"log"
	"os"

	"github.com/begonia599/myplatform/core/auth"
	"github.com/begonia599/myplatform/core/config"
	"github.com/begonia599/myplatform/core/database"
	"github.com/begonia599/myplatform/core/imagebed"
	"github.com/begonia599/myplatform/core/permission"
	"github.com/begonia599/myplatform/core/server"
	"github.com/begonia599/myplatform/core/storage"
)

func main() {
	cfg, err := config.Load("config.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	db, err := database.New(&cfg.Database)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Database connection failed: %v\n", err)
		os.Exit(1)
	}
	defer database.Close(db)

	if err := database.AutoMigrate(db, &auth.User{}, &auth.RefreshToken{}, &auth.UserProfile{}, &auth.OAuthAccount{}, &storage.File{},
		&permission.PermissionDefinition{}, &permission.DefaultRolePolicy{}, &imagebed.Image{}); err != nil {
		fmt.Fprintf(os.Stderr, "Auto-migrate failed: %v\n", err)
		os.Exit(1)
	}

	authService, err := auth.New(&cfg.Auth, db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Auth init failed: %v\n", err)
		os.Exit(1)
	}

	// Initialize root user service (creates root user on first run)
	rootService := auth.NewRootService(db, &cfg.Auth)

	// Initialize OAuth service
	var oauthService *auth.OAuthService
	if cfg.Auth.OAuth.GitHub.ClientID != "" {
		oauthService = auth.NewOAuthService(&cfg.Auth, db)
		log.Println("GitHub OAuth enabled")
	}

	permService, err := permission.New(&cfg.Permission, db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Permission init failed: %v\n", err)
		os.Exit(1)
	}

	// Sync existing users' roles into Casbin
	var users []auth.User
	db.Find(&users)
	for _, u := range users {
		if err := permService.SyncUserRole(u.ID, u.Role); err != nil {
			log.Printf("Warning: failed to sync role for user %d: %v\n", u.ID, err)
		}
	}

	storageService, err := storage.New(&cfg.Storage, db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Storage init failed: %v\n", err)
		os.Exit(1)
	}

	imagebedService, err := imagebed.New(&cfg.ImageBed, &cfg.Storage, db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ImageBed init failed: %v\n", err)
		os.Exit(1)
	}

	srv := server.New(&cfg.Server, db)
	auth.RegisterRoutes(srv.Router(), authService, rootService, oauthService, permService, db)
	permission.RegisterRoutes(srv.Router(), authService, permService, db)
	storage.RegisterRoutes(srv.Router(), authService, storageService, permService)
	imagebed.RegisterRoutes(srv.Router(), authService, imagebedService, permService)
	log.Printf("Starting server on :%d\n", cfg.Server.Port)
	if err := srv.Run(); err != nil {
		log.Fatalf("Server failed: %v\n", err)
	}
}
