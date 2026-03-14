package imagebed

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/begonia599/myplatform/core/auth"
	"github.com/gin-gonic/gin"
)

// Handler exposes HTTP endpoints for image operations.
type Handler struct {
	service     *ImageBedService
	authService *auth.AuthService
}

// NewHandler creates a Handler.
func NewHandler(service *ImageBedService, authService *auth.AuthService) *Handler {
	return &Handler{service: service, authService: authService}
}

// HandleUpload handles POST /api/imagebed/upload
func (h *Handler) HandleUpload(c *gin.Context) {
	user, err := auth.MustCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}

	fh, err := c.FormFile("image")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing image field"})
		return
	}

	record, err := h.service.Upload(c.Request.Context(), fh, user.ID)
	if err != nil {
		if strings.Contains(err.Error(), "exceeds limit") {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": err.Error()})
			return
		}
		if strings.Contains(err.Error(), "unsupported image type") {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, record)
}

// HandleList handles GET /api/imagebed/images
func (h *Handler) HandleList(c *gin.Context) {
	user, err := auth.MustCurrentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	images, total, err := h.service.ListByUser(user.ID, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":      images,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// HandleDelete handles DELETE /api/imagebed/images/:id
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

	if err := h.service.Delete(c.Request.Context(), uint(id), user.ID, user.Role); err != nil {
		if strings.Contains(err.Error(), "permission denied") {
			c.JSON(http.StatusForbidden, gin.H{"error": "只能删除自己的图片"})
			return
		}
		if strings.Contains(err.Error(), "record not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "image not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "image deleted"})
}

// HandleToggleVisibility handles PATCH /api/imagebed/images/:id/visibility
func (h *Handler) HandleToggleVisibility(c *gin.Context) {
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

	var req struct {
		IsPublic bool `json:"is_public"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	img, err := h.service.ToggleVisibility(uint(id), user.ID, user.Role, req.IsPublic)
	if err != nil {
		if strings.Contains(err.Error(), "permission denied") {
			c.JSON(http.StatusForbidden, gin.H{"error": "只能修改自己的图片"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, img)
}

// HandleServe handles GET /api/imagebed/:id
// Public images: served directly without auth.
// Private images: require Bearer token.
func (h *Handler) HandleServe(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	img, err := h.service.GetByID(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "image not found"})
		return
	}

	// Public image: serve directly
	if img.IsPublic {
		h.serveImage(c, img)
		return
	}

	// Private image: verify token
	header := c.GetHeader("Authorization")
	if header == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "此图片为私有，需要认证"})
		return
	}

	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization format"})
		return
	}

	if _, err := h.authService.ValidateAccessToken(parts[1]); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
		return
	}

	h.serveImage(c, img)
}

func (h *Handler) serveImage(c *gin.Context, img *Image) {
	reader, err := h.service.OpenImage(c.Request.Context(), img)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to open image"})
		return
	}
	defer reader.Close()

	// Cache headers
	if img.IsPublic {
		c.Header("Cache-Control", "public, max-age=604800")
	} else {
		c.Header("Cache-Control", "private, no-cache")
	}

	c.Header("Content-Type", img.MimeType)
	c.DataFromReader(http.StatusOK, img.Size, img.MimeType, reader, nil)
}
