package sdk

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

// StorageService wraps all /api/storage endpoints.
type StorageService struct {
	c *Client
}

// Upload uploads a file from the local filesystem.
func (s *StorageService) Upload(filePath string) (*File, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("sdk: open file: %w", err)
	}
	defer f.Close()

	return s.UploadReader(filepath.Base(filePath), f)
}

// UploadReader uploads a file from an io.Reader.
func (s *StorageService) UploadReader(filename string, reader io.Reader) (*File, error) {
	if err := s.c.ensureToken(); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return nil, fmt.Errorf("sdk: create form file: %w", err)
	}
	if _, err := io.Copy(part, reader); err != nil {
		return nil, fmt.Errorf("sdk: copy file data: %w", err)
	}
	writer.Close()

	req, err := http.NewRequest(http.MethodPost, s.c.baseURL+"/api/storage/upload", &buf)
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

	var file File
	if err := decodeJSON(resp.Body, &file); err != nil {
		return nil, err
	}
	return &file, nil
}

// List returns a paginated list of files.
func (s *StorageService) List(page, pageSize int) (*FileListResponse, error) {
	path := fmt.Sprintf("/api/storage/files?page=%d&page_size=%d", page, pageSize)
	var resp FileListResponse
	if err := s.c.doJSON(http.MethodGet, path, nil, &resp, true); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetMeta returns metadata for a single file.
func (s *StorageService) GetMeta(id uint) (*File, error) {
	var resp File
	path := fmt.Sprintf("/api/storage/files/%d", id)
	if err := s.c.doJSON(http.MethodGet, path, nil, &resp, true); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Download returns a ReadCloser for the file content. Caller must close it.
func (s *StorageService) Download(id uint) (io.ReadCloser, string, error) {
	path := fmt.Sprintf("/api/storage/files/%d/download", id)
	resp, err := s.c.doRaw(http.MethodGet, path, true)
	if err != nil {
		return nil, "", err
	}
	filename := resp.Header.Get("Content-Disposition")
	return resp.Body, filename, nil
}

// DownloadTo downloads a file and saves it to the given local path.
func (s *StorageService) DownloadTo(id uint, destPath string) error {
	body, _, err := s.Download(id)
	if err != nil {
		return err
	}
	defer body.Close()

	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("sdk: create file: %w", err)
	}
	defer out.Close()

	if _, err := io.Copy(out, body); err != nil {
		return fmt.Errorf("sdk: write file: %w", err)
	}
	return nil
}

// Delete deletes a file by ID.
func (s *StorageService) Delete(id uint) error {
	path := fmt.Sprintf("/api/storage/files/%d", id)
	return s.c.doJSON(http.MethodDelete, path, nil, nil, true)
}
