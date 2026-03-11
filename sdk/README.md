# MyPlatform Go SDK

MyPlatform SDK 是 [MyPlatform](https://github.com/begonia599/myplatform) 核心平台的 Go 客户端库，封装了认证、权限管理和文件存储的全部 REST API，让你只需几行代码就能在独立微服务中接入平台能力。

---

## 特性

- 🔐 **认证管理** — 注册、登录、Token 刷新、注销、用户档案
- 🛡️ **权限管理** — RBAC 策略 CRUD、角色分配（Admin 接口）
- 📦 **文件存储** — 上传、下载、分页列表、元信息、删除
- 🔄 **自动 Token 刷新** — Access Token 过期前 10 秒自动续期
- 🧵 **线程安全** — 内置读写锁，可安全并发使用
- 👤 **多租户支持** — `WithToken()` 创建用户级轻量客户端

---

## 安装

```bash
go get github.com/begonia599/myplatform/sdk
```

---

## 快速开始

```go
package main

import (
    "fmt"
    "log"

    "github.com/begonia599/myplatform/sdk"
)

func main() {
    // 1. 创建客户端
    client := sdk.New(&sdk.Config{
        BaseURL: "http://localhost:8080",
    })

    // 2. 注册用户
    reg, err := client.Auth.Register("alice", "secure-password", "")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("注册成功: ID=%d, Username=%s\n", reg.ID, reg.Username)

    // 3. 登录（自动存储 Token）
    _, err = client.Auth.Login("alice", "secure-password")
    if err != nil {
        log.Fatal(err)
    }

    // 4. 获取当前用户信息
    me, err := client.Auth.Me()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("当前用户: %s (角色: %s)\n", me.User.Username, me.User.Role)

    // 5. 上传文件
    file, err := client.Storage.Upload("./example.txt")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("上传成功: ID=%d, 文件名=%s\n", file.ID, file.OriginalName)
}
```

---

## 核心概念

### Client

`Client` 是 SDK 的入口，管理 HTTP 连接和 Token 生命周期。

```go
client := sdk.New(&sdk.Config{
    BaseURL:    "http://localhost:8080",  // 必填：核心平台地址
    HTTPClient: customHTTPClient,         // 可选：自定义 http.Client（默认 30s 超时）
})
```

### 自动 Token 刷新

登录后，Client 会自动管理 Token：
- 每次认证请求前检查 Access Token 是否即将过期（提前 10 秒）
- 过期时自动使用 Refresh Token 获取新的 Token 对
- 整个过程对调用者透明

```go
// 登录后，后续所有认证请求自动携带和刷新 Token
client.Auth.Login("alice", "password")
client.Auth.Me()           // ← 自动带 Token
client.Storage.List(1, 20) // ← 自动带 Token，过期自动刷新
```

### WithToken — 多租户模式

在微服务中代理用户请求时，使用 `WithToken()` 创建用户级客户端：

```go
// 全局共享客户端（服务启动时创建一次）
var platform = sdk.New(&sdk.Config{BaseURL: "http://localhost:8080"})

func handleRequest(userAccessToken string) {
    // 为该用户创建轻量客户端（不会自动刷新 Token）
    userClient := platform.WithToken(userAccessToken)

    // 以该用户身份操作
    files, _ := userClient.Storage.List(1, 20)
    me, _ := userClient.Auth.Me()
}
```

> **注意**：`WithToken()` 返回的客户端共享底层 HTTP 连接，但**不会自动刷新** Token。适用于请求级别的短暂使用。

### 手动 Token 管理

如需从持久化存储恢复 Token（如 Redis / 数据库）：

```go
// 恢复 Token（expiresIn 单位为秒）
client.SetTokens(accessToken, refreshToken, expiresInSeconds)

// 读取当前 Access Token
token := client.AccessToken()
```

---

## API 参考

### AuthService — `client.Auth`

认证相关的全部操作。

#### Register — 注册

```go
func (a *AuthService) Register(username, password, role string) (*RegisterResponse, error)
```

创建新用户。`role` 传空字符串时使用默认角色 `"user"`。

```go
resp, err := client.Auth.Register("bob", "my-password", "")
// resp.ID, resp.Username, resp.Role
```

<details>
<summary>RegisterResponse 结构</summary>

```go
type RegisterResponse struct {
    ID       uint   `json:"id"`
    Username string `json:"username"`
    Role     string `json:"role"`
}
```
</details>

---

#### Login — 登录

```go
func (a *AuthService) Login(username, password string) (*TokenPair, error)
```

验证凭据并返回 Token 对。**登录成功后 Token 自动存储到 Client 中**，后续认证请求无需手动传 Token。

```go
tokens, err := client.Auth.Login("bob", "my-password")
// tokens.AccessToken, tokens.RefreshToken, tokens.ExpiresIn
```

<details>
<summary>TokenPair 结构</summary>

```go
type TokenPair struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    TokenType    string `json:"token_type"`
    ExpiresIn    int    `json:"expires_in"` // 秒
}
```
</details>

---

#### Refresh — 手动刷新 Token

```go
func (a *AuthService) Refresh() (*TokenPair, error)
```

手动触发 Token 刷新。通常不需要调用，Client 会自动刷新。

```go
newTokens, err := client.Auth.Refresh()
```

---

#### Logout — 注销

```go
func (a *AuthService) Logout() error
```

吊销当前用户的所有 Refresh Token，并清空 Client 中存储的 Token。

```go
err := client.Auth.Logout()
```

---

#### Me — 获取当前用户

```go
func (a *AuthService) Me() (*MeResponse, error)
```

返回当前认证用户的基本信息和详细档案。

```go
me, err := client.Auth.Me()
// me.User.Username, me.User.Role, me.Profile.Nickname
```

<details>
<summary>MeResponse 结构</summary>

```go
type MeResponse struct {
    User    User        `json:"user"`
    Profile UserProfile `json:"profile"`
}

type User struct {
    ID        uint      `json:"id"`
    Username  string    `json:"username"`
    Email     *string   `json:"email,omitempty"`
    Role      string    `json:"role"`
    Status    string    `json:"status"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
}

type UserProfile struct {
    ID        uint       `json:"id"`
    UserID    uint       `json:"user_id"`
    Nickname  string     `json:"nickname"`
    AvatarURL string     `json:"avatar_url"`
    Bio       string     `json:"bio"`
    Phone     string     `json:"phone"`
    Birthday  *time.Time `json:"birthday,omitempty"`
    UpdatedAt time.Time  `json:"updated_at"`
}
```
</details>

---

#### Verify — 验证 Token（服务间调用）

```go
func (a *AuthService) Verify(token string) (*VerifyResponse, error)
```

验证一个 Access Token 是否有效。**不需要认证**，用于微服务中间件验证用户身份。

```go
result, err := client.Auth.Verify(userToken)
if result.Valid {
    fmt.Printf("用户 %s (ID: %d)\n", result.User.Username, result.User.ID)
}
```

<details>
<summary>VerifyResponse 结构</summary>

```go
type VerifyResponse struct {
    Valid bool       `json:"valid"`
    User  VerifyUser `json:"user"`
}

type VerifyUser struct {
    ID       uint   `json:"id"`
    Username string `json:"username"`
    Role     string `json:"role"`
    Status   string `json:"status"`
}
```
</details>

---

#### GetProfile — 获取用户档案

```go
func (a *AuthService) GetProfile() (*UserProfile, error)
```

```go
profile, err := client.Auth.GetProfile()
```

---

#### UpdateProfile — 更新用户档案

```go
func (a *AuthService) UpdateProfile(update *ProfileUpdate) (*UserProfile, error)
```

只更新非 nil 的字段。

```go
nickname := "小明"
bio := "Hello world"
profile, err := client.Auth.UpdateProfile(&sdk.ProfileUpdate{
    Nickname: &nickname,
    Bio:      &bio,
})
```

<details>
<summary>ProfileUpdate 结构</summary>

```go
type ProfileUpdate struct {
    Nickname  *string `json:"nickname,omitempty"`
    AvatarURL *string `json:"avatar_url,omitempty"`
    Bio       *string `json:"bio,omitempty"`
    Phone     *string `json:"phone,omitempty"`
    Birthday  *string `json:"birthday,omitempty"` // 格式: YYYY-MM-DD
}
```
</details>

---

### StorageService — `client.Storage`

文件存储的全部操作。所有方法需要认证。

#### Upload — 从本地路径上传

```go
func (s *StorageService) Upload(filePath string) (*File, error)
```

```go
file, err := client.Storage.Upload("/path/to/photo.jpg")
fmt.Printf("文件 ID: %d, 大小: %d bytes\n", file.ID, file.Size)
```

---

#### UploadReader — 从 io.Reader 上传

```go
func (s *StorageService) UploadReader(filename string, reader io.Reader) (*File, error)
```

适用于从网络流、内存缓冲等来源上传。

```go
file, err := client.Storage.UploadReader("report.pdf", readerSource)
```

<details>
<summary>File 结构</summary>

```go
type File struct {
    ID           uint      `json:"id"`
    Filename     string    `json:"filename"`
    OriginalName string    `json:"original_name"`
    Size         int64     `json:"size"`
    MimeType     string    `json:"mime_type"`
    StorageType  string    `json:"storage_type"`
    StoragePath  string    `json:"storage_path"`
    UploaderID   uint      `json:"uploader_id"`
    CreatedAt    time.Time `json:"created_at"`
    UpdatedAt    time.Time `json:"updated_at"`
}
```
</details>

---

#### List — 分页列出文件

```go
func (s *StorageService) List(page, pageSize int) (*FileListResponse, error)
```

```go
list, err := client.Storage.List(1, 20)
fmt.Printf("共 %d 个文件，当前页 %d 个\n", list.Total, len(list.Data))
```

<details>
<summary>FileListResponse 结构</summary>

```go
type FileListResponse struct {
    Data     []File `json:"data"`
    Total    int64  `json:"total"`
    Page     int    `json:"page"`
    PageSize int    `json:"page_size"`
}
```
</details>

---

#### GetMeta — 获取文件元信息

```go
func (s *StorageService) GetMeta(id uint) (*File, error)
```

```go
file, err := client.Storage.GetMeta(42)
```

---

#### Download — 下载文件（流式）

```go
func (s *StorageService) Download(id uint) (io.ReadCloser, string, error)
```

返回文件内容流和 `Content-Disposition` 头。**调用者必须关闭返回的 ReadCloser**。

```go
body, contentDisp, err := client.Storage.Download(42)
defer body.Close()
io.Copy(os.Stdout, body)
```

---

#### DownloadTo — 下载文件到本地路径

```go
func (s *StorageService) DownloadTo(id uint, destPath string) error
```

```go
err := client.Storage.DownloadTo(42, "./downloads/photo.jpg")
```

---

#### Delete — 删除文件

```go
func (s *StorageService) Delete(id uint) error
```

```go
err := client.Storage.Delete(42)
```

---

### PermissionService — `client.Permission`

RBAC 权限管理。所有方法需要 **admin** 角色认证。

#### ListPolicies — 查询策略列表

```go
func (p *PermissionService) ListPolicies(role string) ([]Policy, error)
```

`role` 传空字符串返回全部策略。

```go
// 查询所有策略
policies, err := client.Permission.ListPolicies("")

// 只查询 editor 角色的策略
policies, err := client.Permission.ListPolicies("editor")
```

<details>
<summary>Policy 结构</summary>

```go
type Policy struct {
    Role   string `json:"role"`   // 角色: admin, editor, user
    Object string `json:"object"` // 资源: users, articles, storage, permissions
    Action string `json:"action"` // 操作: read, write, delete, manage
}
```
</details>

---

#### AddPolicy — 添加策略

```go
func (p *PermissionService) AddPolicy(role, object, action string) error
```

```go
err := client.Permission.AddPolicy("editor", "articles", "write")
```

---

#### RemovePolicy — 删除策略

```go
func (p *PermissionService) RemovePolicy(role, object, action string) error
```

```go
err := client.Permission.RemovePolicy("editor", "articles", "write")
```

---

#### ListUserRoles — 查询用户角色

```go
func (p *PermissionService) ListUserRoles(userID uint) ([]string, error)
```

```go
roles, err := client.Permission.ListUserRoles(1)
// roles = ["admin"]
```

---

#### AssignRole — 分配角色

```go
func (p *PermissionService) AssignRole(userID uint, role string) error
```

```go
err := client.Permission.AssignRole(5, "editor")
```

---

#### RemoveRole — 移除角色

```go
func (p *PermissionService) RemoveRole(userID uint, role string) error
```

```go
err := client.Permission.RemoveRole(5, "editor")
```

---

## 错误处理

所有 API 方法在服务端返回 HTTP 4xx/5xx 时，会返回 `*sdk.APIError`：

```go
file, err := client.Storage.GetMeta(999)
if err != nil {
    var apiErr *sdk.APIError
    if errors.As(err, &apiErr) {
        fmt.Printf("HTTP %d: %s\n", apiErr.StatusCode, apiErr.Message)
        // HTTP 404: file not found
    }
}
```

```go
type APIError struct {
    StatusCode int    // HTTP 状态码
    Message    string // 错误消息
}
```

---

## 最佳实践

### 微服务集成模式（推荐）

```go
package main

import (
    "github.com/begonia599/myplatform/sdk"
    "github.com/gin-gonic/gin"
)

// 全局客户端 — 服务启动时创建一次
var platform *sdk.Client

func main() {
    platform = sdk.New(&sdk.Config{
        BaseURL: "http://localhost:8080",
    })

    r := gin.Default()
    r.Use(AuthMiddleware())
    r.GET("/my-files", handleMyFiles)
    r.Run(":8081")
}

// 认证中间件 — 验证用户 Token
func AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        token := extractBearerToken(c)
        result, err := platform.Auth.Verify(token)
        if err != nil || !result.Valid {
            c.AbortWithStatusJSON(401, gin.H{"error": "unauthorized"})
            return
        }
        c.Set("user", result.User)
        c.Set("token", token)
        c.Next()
    }
}

// 业务处理 — 使用 WithToken 代理用户请求
func handleMyFiles(c *gin.Context) {
    userClient := platform.WithToken(c.GetString("token"))
    files, err := userClient.Storage.List(1, 20)
    if err != nil {
        c.JSON(500, gin.H{"error": err.Error()})
        return
    }
    c.JSON(200, files)
}
```

### 要点总结

| 场景 | 方法 |
|------|------|
| 服务间 Token 验证 | `client.Auth.Verify(token)` — 无需认证 |
| 代理用户请求 | `client.WithToken(token)` — 轻量级，不自动刷新 |
| 服务自身操作 | `client.Auth.Login()` — 自动管理 Token |
| 恢复已有 Token | `client.SetTokens(access, refresh, expiresIn)` |

---

## REST API 路由速查表

| 方法 | 路径 | 认证 | SDK 方法 |
|------|------|------|----------|
| POST | `/auth/register` | ✗ | `Auth.Register()` |
| POST | `/auth/login` | ✗ | `Auth.Login()` |
| POST | `/auth/refresh` | ✗ | `Auth.Refresh()` |
| POST | `/auth/verify` | ✗ | `Auth.Verify()` |
| POST | `/auth/logout` | ✓ | `Auth.Logout()` |
| GET | `/auth/me` | ✓ | `Auth.Me()` |
| GET | `/auth/profile` | ✓ | `Auth.GetProfile()` |
| PUT | `/auth/profile` | ✓ | `Auth.UpdateProfile()` |
| POST | `/api/storage/upload` | ✓ | `Storage.Upload()` / `Storage.UploadReader()` |
| GET | `/api/storage/files` | ✓ | `Storage.List()` |
| GET | `/api/storage/files/:id` | ✓ | `Storage.GetMeta()` |
| GET | `/api/storage/files/:id/download` | ✓ | `Storage.Download()` / `Storage.DownloadTo()` |
| DELETE | `/api/storage/files/:id` | ✓ | `Storage.Delete()` |
| GET | `/api/permissions/policies` | ✓ Admin | `Permission.ListPolicies()` |
| POST | `/api/permissions/policies` | ✓ Admin | `Permission.AddPolicy()` |
| DELETE | `/api/permissions/policies` | ✓ Admin | `Permission.RemovePolicy()` |
| GET | `/api/permissions/roles/:user_id` | ✓ Admin | `Permission.ListUserRoles()` |
| POST | `/api/permissions/roles` | ✓ Admin | `Permission.AssignRole()` |
| DELETE | `/api/permissions/roles` | ✓ Admin | `Permission.RemoveRole()` |
