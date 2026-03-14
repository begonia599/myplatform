package sdk

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
)

// ImageBedService wraps all /api/imagebed endpoints.
type ImageBedService struct {
	c *Client
}

// Upload uploads an image from the local filesystem.
func (s *ImageBedService) Upload(filePath string) (*Image, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("sdk: open file: %w", err)
	}
	defer f.Close()

	return s.UploadReader(filepath.Base(filePath), f)
}

// UploadReader uploads an image from an io.Reader.
func (s *ImageBedService) UploadReader(filename string, reader io.Reader) (*Image, error) {
	if err := s.c.ensureToken(); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Detect MIME type from file extension instead of using CreateFormFile
	// which defaults to application/octet-stream
	mimeType := mime.TypeByExtension(filepath.Ext(filename))
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="image"; filename="%s"`,
		strings.NewReplacer("\\", "\\\\", `"`, "\\\"").Replace(filename)))
	h.Set("Content-Type", mimeType)

	part, err := writer.CreatePart(h)
	if err != nil {
		return nil, fmt.Errorf("sdk: create form part: %w", err)
	}
	if _, err := io.Copy(part, reader); err != nil {
		return nil, fmt.Errorf("sdk: copy file data: %w", err)
	}
	writer.Close()

	req, err := http.NewRequest(http.MethodPost, s.c.baseURL+"/api/imagebed/upload", &buf)
	if err != nil {
		return nil, fmt.Errorf("sdk: create request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	s.c.mu.RLock()
	req.Header.Set("Authorization", "Bearer "+s.c.accessToken)
	s.c.mu.RUnlock()

	resp, err := s.c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sdk: http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, parseErrorResponse(resp)
	}

	var img Image
	if err := decodeJSON(resp.Body, &img); err != nil {
		return nil, err
	}
	return &img, nil
}

// List returns a paginated list of the authenticated user's images.
func (s *ImageBedService) List(page, pageSize int) (*ImageListResponse, error) {
	path := fmt.Sprintf("/api/imagebed/images?page=%d&page_size=%d", page, pageSize)
	var resp ImageListResponse
	if err := s.c.doJSON(http.MethodGet, path, nil, &resp, true); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Delete deletes an image by ID.
func (s *ImageBedService) Delete(id uint) error {
	path := fmt.Sprintf("/api/imagebed/images/%d", id)
	return s.c.doJSON(http.MethodDelete, path, nil, nil, true)
}

// ToggleVisibility changes the public/private status of an image.
func (s *ImageBedService) ToggleVisibility(id uint, isPublic bool) (*Image, error) {
	path := fmt.Sprintf("/api/imagebed/images/%d/visibility", id)
	var resp Image
	err := s.c.doJSON(http.MethodPatch, path, map[string]bool{
		"is_public": isPublic,
	}, &resp, true)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// PublicURL returns the public access URL for an image.
func (s *ImageBedService) PublicURL(id uint) string {
	return fmt.Sprintf("%s/api/imagebed/%d", s.c.baseURL, id)
}
