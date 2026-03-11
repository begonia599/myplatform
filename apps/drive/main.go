package main

import (
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/begonia599/myplatform/sdk"
	"github.com/gin-gonic/gin"
)

// platform 是全局的 SDK 客户端，所有请求共享，指向统一后端
var platform *sdk.Client

func main() {
	platform = sdk.New(&sdk.Config{
		BaseURL: "http://localhost:8080", // 统一后端地址
	})

	r := gin.Default()

	// ─── 公开接口 ───
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// ─── 需要认证的接口 ───
	drive := r.Group("/drive")
	drive.Use(AuthRequired())
	{
		drive.GET("/files", handleListFiles)
		drive.POST("/upload", handleUpload)
		drive.GET("/files/:id", handleGetFile)
		drive.GET("/files/:id/download", handleDownload)
		drive.DELETE("/files/:id", handleDeleteFile)
		drive.GET("/me", handleMe)
	}

	log.Println("Drive service running on :8081")
	r.Run(":8081")
}

// ==================== 中间件 ====================

// AuthRequired 使用 SDK 的 Verify 接口验证用户 token
func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if header == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			return
		}

		parts := strings.SplitN(header, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization format"})
			return
		}
		token := parts[1]

		// 调用统一后端验证 token
		result, err := platform.Auth.Verify(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token verification failed"})
			return
		}
		if !result.Valid {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid token"})
			return
		}

		// 把用户信息和 token 存到 context 中
		c.Set("user", result.User)
		c.Set("token", token)
		c.Next()
	}
}

// userClient 从 context 中取出 token，创建一个用该用户身份操作的 SDK 客户端
func userClient(c *gin.Context) *sdk.Client {
	token := c.GetString("token")
	return platform.WithToken(token)
}

// currentUser 从 context 中取出已验证的用户信息
func currentUser(c *gin.Context) sdk.VerifyUser {
	u, _ := c.Get("user")
	return u.(sdk.VerifyUser)
}

// ==================== 业务接口 ====================

// GET /drive/me — 获取当前用户信息（演示 Auth.Me）
func handleMe(c *gin.Context) {
	me, err := userClient(c).Auth.Me()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, me)
}

// GET /drive/files — 列出文件
func handleListFiles(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	list, err := userClient(c).Storage.List(page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 这里可以加网盘特有的业务逻辑，比如：
	// - 根据 folder_id 过滤
	// - 附加文件夹层级信息
	// - 拼接缩略图 URL
	c.JSON(http.StatusOK, list)
}

// POST /drive/upload — 上传文件
func handleUpload(c *gin.Context) {
	fh, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing file"})
		return
	}

	// 打开上传的文件
	src, err := fh.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read file"})
		return
	}
	defer src.Close()

	// 通过 SDK 上传到统一后端的存储服务
	file, err := userClient(c).Storage.UploadReader(fh.Filename, src)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 这里可以加网盘业务逻辑，比如：
	// - 记录文件所属文件夹
	// - 更新用户已用空间
	// - 生成缩略图任务

	c.JSON(http.StatusCreated, file)
}

// GET /drive/files/:id — 获取文件元信息
func handleGetFile(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	file, err := userClient(c).Storage.GetMeta(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
		return
	}
	c.JSON(http.StatusOK, file)
}

// GET /drive/files/:id/download — 下载文件
func handleDownload(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	body, contentDisp, err := userClient(c).Storage.Download(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
		return
	}
	defer body.Close()

	if contentDisp != "" {
		c.Header("Content-Disposition", contentDisp)
	}
	c.Status(http.StatusOK)
	c.Stream(func(w io.Writer) bool {
		io.Copy(w, body)
		return false
	})
}

// DELETE /drive/files/:id — 删除文件
func handleDeleteFile(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	if err := userClient(c).Storage.Delete(uint(id)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 这里可以加网盘业务逻辑：
	// - 释放用户配额
	// - 删除缩略图
	// - 从文件夹中移除记录

	c.JSON(http.StatusOK, gin.H{"message": "file deleted"})
}
