# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MyPlatform is a Go backend platform providing authentication, RBAC authorization, and file storage as reusable services. It exposes a REST API consumed by independent microservices through a Go SDK (`sdk/` package). An example Drive app (`apps/drive/`) demonstrates this pattern.

**Module:** `github.com/begonia599/myplatform` | **Go:** 1.25 | **Framework:** Gin + GORM + PostgreSQL

## Build & Run Commands

```bash
# Build
go build -o myplatform .

# Run (requires PostgreSQL, reads config.yaml)
./myplatform

# Run with Docker Compose (starts PostgreSQL + app)
docker-compose up --build

# Run the example Drive app
go run ./apps/drive

# Dependencies
go mod tidy
```

There are no tests, no Makefile, and no linting config in the project yet.

## Architecture

```
main.go          →  Startup: config → DB → migrate → auth → permission → storage → server
core/
  config/        →  YAML config loading, applies defaults for all subsystems
  server/        →  Gin engine wrapper, /health endpoint
  database/      →  GORM PostgreSQL connection, pooling, auto-migration
  auth/          →  JWT auth (bcrypt passwords, access+refresh token rotation, user profiles)
  permission/    →  Casbin RBAC (roles: admin/user/editor, resources: users/articles/storage/permissions)
  storage/       →  Pluggable file storage (local filesystem / S3), upload/download/delete with pagination
sdk/             →  Go client library wrapping all REST endpoints (thread-safe token management, auto-refresh)
apps/drive/      →  Example microservice using SDK: Verify-based auth middleware + WithToken per-request clients
```

### Module Pattern

Each core module follows: `config.go` → `models.go` → `service.go` → `handler.go` → `routes.go`

- **Service** contains business logic, receives config + DB via constructor
- **Handler** translates HTTP ↔ service calls (Gin context binding)
- **Routes** registers Gin route groups with middleware

### Key Design Decisions

- **Auth middleware** injects user claims into Gin context via `auth.AuthMiddleware()` + `auth.RequireRole()`
- **Permission middleware** uses `permission.RequirePermission(object, action)` checking Casbin policies
- **Storage interface** (`storage.Storage`) abstracts backends — `LocalStorage` and `S3Storage` implement it
- **SDK multi-tenant pattern**: global `sdk.Client` for service init, `client.WithToken(token)` for per-request user-scoped clients (no auto-refresh on scoped clients)
- **Token auto-refresh**: SDK refreshes access tokens 10 seconds before expiry

### Route Structure

- `/auth/*` — public (register, login, refresh, verify) + authenticated (logout, me, profile)
- `/api/permissions/*` — admin-only (policy CRUD, role assignment)
- `/api/storage/*` — authenticated (upload, list, download, delete)
- `/health` — unauthenticated health check

### Configuration

`config.yaml` at project root. Database defaults to `localhost:5432/myplatform`. Docker Compose maps PostgreSQL to host port 15432 and app to 18080.
