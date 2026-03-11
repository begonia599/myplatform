package server

import (
	"fmt"
	"net/http"

	"github.com/begonia599/myplatform/core/config"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type Server struct {
	engine *gin.Engine
	db     *gorm.DB
	port   int
}

// New creates a new Server with the given config and database connection.
func New(cfg *config.ServerConfig, db *gorm.DB) *Server {
	gin.SetMode(cfg.Mode)
	engine := gin.Default()

	s := &Server{
		engine: engine,
		db:     db,
		port:   cfg.Port,
	}

	s.registerRoutes()
	RegisterAdminRoutes(engine)
	return s
}

// Router returns the underlying gin.Engine so other modules can register routes.
func (s *Server) Router() *gin.Engine {
	return s.engine
}

// Run starts the HTTP server.
func (s *Server) Run() error {
	addr := fmt.Sprintf(":%d", s.port)
	return s.engine.Run(addr)
}

func (s *Server) registerRoutes() {
	s.engine.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
}
