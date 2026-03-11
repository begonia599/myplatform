package server

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/gin-gonic/gin"
)

//go:embed all:admin_dist
var adminFS embed.FS

// RegisterAdminRoutes serves the embedded admin SPA at /admin/*
func RegisterAdminRoutes(router *gin.Engine) {
	// Strip the "admin_dist" prefix to serve files from the root of the embedded FS
	subFS, err := fs.Sub(adminFS, "admin_dist")
	if err != nil {
		panic("failed to create admin sub-filesystem: " + err.Error())
	}

	fileServer := http.FileServer(http.FS(subFS))

	router.GET("/admin", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/admin/")
	})

	router.GET("/admin/*filepath", func(c *gin.Context) {
		filepath := c.Param("filepath")

		// Try to serve the file
		f, err := subFS.(fs.ReadFileFS).ReadFile(filepath[1:]) // strip leading "/"
		if err != nil || len(f) == 0 {
			// SPA fallback: serve index.html for any unknown path
			c.FileFromFS("/", http.FS(subFS))
			return
		}

		// Serve the actual file
		c.Request.URL.Path = filepath
		fileServer.ServeHTTP(c.Writer, c.Request)
	})
}
