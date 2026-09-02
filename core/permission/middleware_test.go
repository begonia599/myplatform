package permission

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func serviceTokenRouter(token string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/svc", RequireServiceToken(token), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	return r
}

func doPost(r *gin.Engine, header string) int {
	req := httptest.NewRequest(http.MethodPost, "/svc", nil)
	if header != "" {
		req.Header.Set(ServiceTokenHeader, header)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func TestRequireServiceToken_Configured(t *testing.T) {
	r := serviceTokenRouter("s3cr3t")

	if got := doPost(r, ""); got != http.StatusUnauthorized {
		t.Fatalf("missing header: want 401, got %d", got)
	}
	if got := doPost(r, "wrong"); got != http.StatusUnauthorized {
		t.Fatalf("wrong token: want 401, got %d", got)
	}
	if got := doPost(r, "s3cr3t-but-longer"); got != http.StatusUnauthorized {
		t.Fatalf("prefix token: want 401, got %d", got)
	}
	if got := doPost(r, "s3cr3t"); got != http.StatusOK {
		t.Fatalf("correct token: want 200, got %d", got)
	}
}

func TestRequireServiceToken_EmptyIsNoop(t *testing.T) {
	r := serviceTokenRouter("")
	if got := doPost(r, ""); got != http.StatusOK {
		t.Fatalf("empty configured token must pass through: want 200, got %d", got)
	}
	if got := doPost(r, "anything"); got != http.StatusOK {
		t.Fatalf("empty configured token must ignore header: want 200, got %d", got)
	}
}
