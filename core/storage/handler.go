package storage

import (
	"net/http"
	"strconv"

	"github.com/begonia599/myplatform/core/auth"
	"github.com/begonia599/myplatform/core/permission"
	"github.com/gin-gonic/gin"
)

// Handler exposes HTTP endpoints for file operations.
type Handler struct {
	service     *StorageService
	permService *permission.PermissionService
}

// NewHandler creates a Handler.
func NewHandler(service *StorageService, permService *permission.PermissionService) *Handler {
	return &Handler{service: service, permService: permService}
}

// HandleUpload handles POST /api/storage/upload
func (h *Handler) HandleUpload(c *gin.Context) {
	user, err := auth.MustCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}

	fh, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing file field"})
		return
	}

	record, err := h.service.Upload(c.Request.Context(), fh, user.ID)
	if err != nil {
		if record == nil && fh.Size > h.service.cfg.MaxFileSize {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, record)
}

// HandleList handles GET /api/storage/files
func (h *Handler) HandleList(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	files, total, err := h.service.List(page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":      files,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// HandleGetMeta handles GET /api/storage/files/:id
func (h *Handler) HandleGetMeta(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	f, err := h.service.GetByID(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
		return
	}

	c.JSON(http.StatusOK, f)
}

// HandleDownload handles GET /api/storage/files/:id/download
func (h *Handler) HandleDownload(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	f, err := h.service.GetByID(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
		return
	}

	reader, err := h.service.OpenFile(c.Request.Context(), f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to open file"})
		return
	}
	defer reader.Close()

	c.Header("Content-Disposition", "attachment; filename=\""+f.OriginalName+"\"")
	c.Header("Content-Type", f.MimeType)
	c.DataFromReader(http.StatusOK, f.Size, f.MimeType, reader, nil)
}

// HandleDelete handles DELETE /api/storage/files/:id
func (h *Handler) HandleDelete(c *gin.Context) {
	user, err := auth.MustCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	f, err := h.service.GetByID(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
		return
	}

	// Owner can delete, or user with storage:delete permission
	if f.UploaderID != user.ID {
		allowed, permErr := h.permService.CheckPermission(user.ID, "storage", "delete")
		if permErr != nil || !allowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "permission denied"})
			return
		}
	}

	if err := h.service.Delete(uint(id)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "file deleted"})
}
