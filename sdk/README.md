# MyPlatform Go SDK

MyPlatform SDK 是 [MyPlatform](https://github.com/begonia599/myplatform) 核心平台的 Go 客户端库，封装了认证、OAuth、权限管理、文件存储和图床的全部 REST API，让你只需几行代码就能在独立微服务中接入平台能力。

> 本文档对应 SDK **v0.10.0**，覆盖全部 43 个服务方法。

---

## 特性

- 🔐 **认证管理** — 注册、登录、Token 刷新、注销、用户档案、修改密码
- 🔗 **OAuth 登录与绑定** — GitHub / Discord 第三方登录、账号绑定与解绑、获取用户的第三方 Access Token
- 🔀 **账号合并** — OAuth 账号并入本地账号、历史用户 ID 解析、墓碑清理
- 🛡️ **权限管理** — 模块权限注册、服务间权限校验、RBAC 策略查询 / 添加 / 删除、角色分配、默认角色策略
- 📦 **文件存储** — 上传、下载、分页列表、元信息、删除
- 🖼️ **图床** — 图片上传、列表、删除、公开/私有切换、公开访问 URL
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

`Client` 是 SDK 的入口，管理 HTTP 连接和 Token 生命周期。四个服务通过字段暴露：`client.Auth`、`client.Storage`、`client.Permission`、`client.ImageBed`。

```go
client := sdk.New(&sdk.Config{
    BaseURL:      "http://localhost:8080",  // 必填：核心平台地址，末尾不要带 /
    HTTPClient:   customHTTPClient,         // 可选：自定义 http.Client（默认 30s 超时）
    ServiceToken: os.Getenv("PLATFORM_SERVICE_TOKEN"), // 可选：服务间接口的 X-Service-Token
})
```

> `BaseURL` 与各接口路径是直接字符串拼接，末尾多一个 `/` 会请求到 `//auth/login`。

> `ServiceToken` 会作为 `X-Service-Token` 头附加到每个请求上。平台配置了 `permission.service_token` 时，`RegisterPermissions` 和 `CheckPermission` 必须带上它，否则 `401`；平台未配置时留空即可。

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

会把 Token 写入 Client 的公开入口有四个：`Auth.Login()`、`Auth.OAuthExchange()`、`Auth.Refresh()`、`Client.SetTokens()`；此外每次认证请求前的内部自动刷新成功后，也会用新的 Token 对覆盖 Client 中的存储。`Auth.Logout()` 成功后会清空这些字段。

如果 Access Token 缺失、已过期或将在 10 秒内过期，且 Client 中没有 Refresh Token，需要认证的调用会直接返回 `APIError{StatusCode: 401, Message: "not authenticated, call Login first"}`，不会发出网络请求。例如用 `SetTokens(access, "", expiresIn)` 只写入了 Access Token，到期后即会触发。

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

> **注意**：`WithToken()` 返回的客户端共享底层 HTTP 连接，但**不会自动刷新** Token，也没有 Refresh Token。用户 Token 过期时平台会返回 `401`，由业务方引导用户重新登录；在它拿到 Refresh Token 之前，调用 `Auth.Refresh()` 会在本地直接返回 `APIError{401, "no refresh token available"}`。适用于请求级别的短暂使用。
>
> 它仍是普通的 `*Client`：一旦在它上面调用 `SetTokens()`（或 `Auth.Login()` / `Auth.OAuthExchange()`，二者内部同样调用 `SetTokens`）并写入非空 Refresh Token，它就会像 `sdk.New()` 创建的客户端一样自动刷新。「账号合并」一节的示例正是这样把 `userClient` 切换到主账号身份的。

> **注意**：`Auth.Login()` 和 `Auth.OAuthExchange()` 会把拿到的 Token **写入所调用的那个 Client**。在全局共享客户端上替终端用户调用它们，会覆盖客户端原有的 Token。如果全局客户端只用于免认证的服务间调用（`Verify`、`CheckPermission`、`RegisterPermissions`）和派生 `WithToken()`，这没有影响；若还需要以服务自身身份调用认证接口，请为服务身份单独创建一个 Client。

### 手动 Token 管理

如需从持久化存储恢复 Token（如 Redis / 数据库）：

```go
// 恢复 Token（expiresIn 单位为秒）
client.SetTokens(accessToken, refreshToken, expiresInSeconds)

// 读取当前 Access Token
token := client.AccessToken()

// 读取平台地址（拼接对外 URL 时可用）
base := client.GetBaseURL()
```

### 鉴权层级

平台接口分四档，本文档和文末速查表统一用以下符号标注：

| 标注 | 含义 | 说明 |
|------|------|------|
| ✗ | 无需认证 | 服务间调用或登录前流程，Client 无需处于登录态。其中 `RegisterPermissions` / `CheckPermission` 在平台配置了 `permission.service_token` 时要求 `X-Service-Token`，由 `Config.ServiceToken` 自动附加 |
| ✓ | 需登录 | 携带有效 Access Token 即可 |
| ✓ Admin | 需 `admin` 角色 | root 用户自动放行 |
| ✓ 权限 | 需登录 + 具体 Casbin 权限 | admin / root 自动放行 |

SDK 方法内部已按接口要求决定是否附带 `Authorization: Bearer` 头，调用方无需关心。

---

## API 参考

### AuthService — `client.Auth`

认证相关的全部操作，分为基础认证、OAuth、账号合并三部分。

#### Register — 注册

```go
func (a *AuthService) Register(username, password, role string) (*RegisterResponse, error)
```

✗ `POST /auth/register`

创建新用户。`role` 传空字符串时使用默认角色 `"user"`。公开注册接口**不允许指定 `admin`**，传入 `"admin"` 会被平台静默降级为 `"user"`。

可能的错误：`403` 平台已关闭注册、`409` 用户名已存在。

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

✗ `POST /auth/login`

验证凭据并返回 Token 对。**登录成功后 Token 自动存储到 Client 中**，后续认证请求无需手动传 Token。凭据错误返回 `401`。

> 特例：若 `username` 是平台 root 账号且 root 尚未设置密码（首次部署的默认状态），平台不校验密码，而是返回 `200 {"require_otp": true}`，响应中不含 Token。SDK 会把这种情况报成 `*APIError{401, "login did not return tokens (root account requires OTP setup)"}`，不会把空 Token 写入 Client。业务服务不应通过 SDK 登录 root。

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

✗ `POST /auth/refresh`（使用 Client 内已存的 Refresh Token）

手动触发 Token 刷新。通常不需要调用，Client 会自动刷新。刷新成功后新的 Token 对会自动写入 Client，无需再调用 `SetTokens()`。Client 中没有 Refresh Token 时返回 `APIError{401, "no refresh token available"}`；Refresh Token 已失效或被吊销时平台返回 `401`。

```go
newTokens, err := client.Auth.Refresh()
```

---

#### Logout — 注销

```go
func (a *AuthService) Logout() error
```

✓ `POST /auth/logout`

吊销当前用户的所有 Refresh Token，并清空 Client 中存储的 Token。

```go
err := client.Auth.Logout()
```

---

#### Me — 获取当前用户

```go
func (a *AuthService) Me() (*MeResponse, error)
```

✓ `GET /auth/me`

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

✗ `POST /auth/verify`

验证一个 Access Token 是否有效并返回归属用户。**不需要认证**，是微服务鉴权中间件的标准入口。

> 传入空字符串 token 时平台返回 HTTP `400`（请求体校验失败）；Token 无效或过期时返回 `401`；用户被禁用时返回 `403`。三种情况 SDK 都会返回 `*APIError`，此时 `result` 为 `nil`。因此**必须先判断 `err`**；`result.Valid` 只在 `err == nil` 时可读，且此时恒为 `true`。中间件应先检查 `Authorization` 头存在且非空再调用 `Verify`，或把 `400` 一并视为未认证。

```go
result, err := client.Auth.Verify(userToken)
if err != nil {
    // 400 空 token，401 无效 / 过期，403 用户被禁用
    return
}
fmt.Printf("用户 %s (ID: %d, 角色: %s)\n", result.User.Username, result.User.ID, result.User.Role)
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

✓ `GET /auth/profile`

```go
profile, err := client.Auth.GetProfile()
```

---

#### UpdateProfile — 更新用户档案

```go
func (a *AuthService) UpdateProfile(update *ProfileUpdate) (*UserProfile, error)
```

✓ `PUT /auth/profile`

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

#### ChangePassword — 修改 / 首次设置密码

```go
func (a *AuthService) ChangePassword(oldPassword, newPassword string) error
```

✓ `PUT /auth/password`

新密码至少 6 位。

- 已有密码的用户必须传 `oldPassword`：为空返回 `400`，旧密码错误返回 `401`。
- OAuth-only 用户（从未设置过密码）传空字符串 `oldPassword` 即可**首次设置密码**。设置密码后才允许解绑最后一个 OAuth 账号。

```go
// 修改密码
err := client.Auth.ChangePassword("old-pass", "new-pass")

// OAuth 用户首次设置密码
err = client.Auth.ChangePassword("", "new-pass")
```

---

### OAuth — `client.Auth`

平台目前支持 `github` 和 `discord` 两个 provider。登录流程分三步：

1. 业务后端调用 `OAuthAuthorize(provider, redirectURI)` 拿到第三方授权页地址，前端把浏览器重定向过去。
2. 用户在第三方授权后，平台的回调接口处理完毕，302 回跳到 `redirectURI`，成功时附带一次性 `?exchange_code=...`。
3. 前端把 `exchange_code` 交给业务后端，后端调用 `OAuthExchange(code)` 换取 Token 对。

回跳地址并非总带 `exchange_code`：平台用第三方 code 换 token、拉取用户信息或建用户失败时，会回跳到 `redirectURI?error=oauth_failed`；生成 exchange_code 失败时为 `?error=internal_error`。前端应先检查 `error` 参数再读取 `exchange_code`。用户在第三方页面取消授权、或 `state` 无效时，平台回调接口直接返回 `400` 纯文本，**不会**回跳到 `redirectURI`。

绑定模式（`OAuthBindAuthorize`）的前两步相同，但回调时不签发 Token，而是把第三方账号挂到当前登录用户名下，并以 `?bind_result=...` 回跳。

#### OAuthAuthorize — 获取授权地址（登录模式）

```go
func (a *AuthService) OAuthAuthorize(provider, redirectURI string) (*OAuthAuthorizeResponse, error)
```

✗ `GET /auth/oauth/{provider}?redirect_uri={redirectURI}`

返回第三方授权页地址。用户授权完成后，平台会 302 回跳到 `redirectURI?exchange_code=...`；失败时为 `redirectURI?error=oauth_failed`（见上方流程说明）。

> `redirectURI` 的 host（或 host:port）必须在平台 `auth.oauth.allowed_redirect_hosts` 白名单内，否则返回 `400 redirect_uri not allowed`；平台未配置白名单时返回 `503`。这是防止攻击者把回跳地址指到自己服务器、截获 `exchange_code` 的唯一屏障。SDK 会对 `redirectURI` 做 URL 编码，可直接传带查询参数的地址。

可能的错误：`400` 不支持的 provider、缺少 `redirect_uri` 或 `redirect_uri` 不在白名单，`404` 平台未配置 OAuth，`503` 白名单未配置。

```go
resp, err := client.Auth.OAuthAuthorize("github", "https://app.example.com/oauth/callback")
// 把浏览器重定向到 resp.AuthURL
```

<details>
<summary>OAuthAuthorizeResponse 结构</summary>

```go
type OAuthAuthorizeResponse struct {
    AuthURL string `json:"auth_url"`
}
```
</details>

---

#### OAuthExchange — 用 exchange_code 换取 Token

```go
func (a *AuthService) OAuthExchange(exchangeCode string) (*TokenPair, error)
```

✗ `POST /auth/oauth/exchange`

`exchange_code` 一次性有效。成功后 Token **自动存储到 Client 中**（见「WithToken」一节关于共享客户端的提醒）。

```go
tokens, err := client.Auth.OAuthExchange(code)
```

---

#### OAuthBindAuthorize — 获取授权地址（绑定模式）

```go
func (a *AuthService) OAuthBindAuthorize(provider, redirectURI string, extraScopes ...string) (*OAuthAuthorizeResponse, error)
```

✓ `GET /auth/oauth/{provider}/bind?redirect_uri={redirectURI}&scopes={extraScopes}`

回调时把第三方账号绑定到**当前登录用户**，不创建新用户，也不签发 Token。`redirectURI` 同样受白名单约束。

`extraScopes` 可申请超出登录默认值的额外 scope，多个值以空格连接后 URL 编码。例如 Discord 服务器成员校验需要：

```go
resp, err := userClient.Auth.OAuthBindAuthorize(
    "discord", "https://app.example.com/settings",
    "guilds", "guilds.members.read",
)
```

回跳时 `redirectURI` 上会带 `?bind_result=`，取值如下：

| bind_result | 含义 |
|-------------|------|
| `success` | 绑定成功。若该第三方账号原属于一个 OAuth-only 的占位用户（无密码、非 root、未被合并过），且当前用户在该 provider 下尚无绑定，平台会把该占位用户**合并进当前用户**并同样返回 `success` |
| `already_bound` | 该第三方账号已绑定到当前用户，平台会顺带更新其 Token 与 scope |
| `conflict` | 该第三方账号已绑定到其他用户；或当前用户在该 provider 下已绑定了另一个账号（每个 provider 只能绑一个，需先解绑） |
| `oauth_failed` | 平台向第三方交换 token 或拉取用户信息失败 |
| `internal_error` | 平台内部错误 |

用户在第三方授权页取消或拒绝时，provider 回跳到平台只带 `error=access_denied` 而没有 `code`，平台回调会直接返回 `400` 纯文本，**不会**回跳到 `redirectURI`，也没有 `bind_result`。

> **绑定触发的隐式合并**：与 `LinkExisting` 不同，这里的合并不会在回跳中告知被合并的用户 ID。被合并的占位用户变成墓碑，其角色、OAuth 记录、文件与图片都迁到当前用户。业务库中若存有该占位用户的 `user_id`，需用 `GetCanonicalUser` 解析到当前有效账号。

---

#### GetOAuthAccounts — 已绑定账号列表

```go
func (a *AuthService) GetOAuthAccounts() (*OAuthAccountsResponse, error)
```

✓ `GET /auth/oauth/accounts`

返回当前用户已绑定的全部第三方账号。附带的 `HasPassword` 可用于前端判断是否允许解绑最后一个第三方账号。

```go
accounts, err := client.Auth.GetOAuthAccounts()
for _, a := range accounts.Accounts {
    fmt.Println(a.Provider, a.Email)
}
```

<details>
<summary>OAuthAccountsResponse 结构</summary>

```go
type OAuthAccountsResponse struct {
    Accounts    []OAuthAccountInfo `json:"accounts"`
    HasPassword bool               `json:"has_password"`
}

type OAuthAccountInfo struct {
    ID             uint   `json:"id"`
    Provider       string `json:"provider"`
    ProviderUserID string `json:"provider_user_id"`
    Email          string `json:"email"`
    AvatarURL      string `json:"avatar_url"`
    CreatedAt      string `json:"created_at"`
    UpdatedAt      string `json:"updated_at"`
}
```
</details>

---

#### GetOAuthToken — 获取用户的第三方 Access Token

```go
func (a *AuthService) GetOAuthToken(provider string) (*OAuthTokenResponse, error)
```

✓ `GET /auth/oauth/accounts/{provider}/token`

返回当前用户在第三方平台的 Access Token（平台侧已按需自动刷新），供受信任的下游服务代表用户调用第三方 API，例如校验 Discord 服务器成员身份。

| 状态码 | 含义 |
|--------|------|
| `404` | 该 provider 未绑定（未知的 provider 名同样返回 `404`） |
| `410` | 无存储的 Token（历史遗留记录，需用户重新授权） |
| `401` | Token 刷新失败（用户在第三方侧撤销了授权） |

```go
tok, err := userClient.Auth.GetOAuthToken("discord")
// tok.AccessToken, tok.Scopes, tok.ExpiresAt
```

<details>
<summary>OAuthTokenResponse 结构</summary>

```go
type OAuthTokenResponse struct {
    AccessToken string     `json:"access_token"`
    Scopes      []string   `json:"scopes"`
    ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}
```
</details>

---

#### UnlinkOAuth — 解绑第三方账号

```go
func (a *AuthService) UnlinkOAuth(provider string) error
```

✓ `DELETE /auth/oauth/accounts/{provider}`

若用户没有密码且这是唯一的 OAuth 账号，平台会拒绝解绑并返回 `400`，提示先设置密码。解绑一个未绑定的 provider 同样返回 `400`（`oauth account not found`），不是 `404`。「唯一登录方式」检查先于查库执行：无密码且只绑了一个第三方账号的用户，无论传入哪个 provider 都会收到提示先设置密码的 `400`。

```go
err := client.Auth.UnlinkOAuth("github")
```

---

### 账号合并 — `client.Auth`

场景：用户先用 OAuth 登录生成了新账号，之后发现自己早有本地账号。合并把 OAuth 账号（secondary）并入本地账号（primary），secondary 变成墓碑（tombstone）。业务方需把自己数据库里指向 secondary 的 `user_id` 迁到 primary，再清理墓碑。

#### LinkExisting — 合并到已有本地账号

```go
func (a *AuthService) LinkExisting(username, password string) (*LinkExistingResponse, error)
```

✓ `POST /auth/oauth/link-existing`

当前登录用户**必须是 OAuth-only 用户**（没有密码），否则返回 `400` 并提示改用绑定模式。`username` / `password` 是目标本地账号的凭据，校验失败返回 `401`。

其他错误：`400` 不能合并到自己、`403` 当前用户是 root、`404` 用户不存在、`409` 其中一方已被合并过。

> 返回的 `Tokens` **不会自动存入 Client**。这是刻意设计：调用方通常要先以 secondary 身份完成业务侧数据迁移，再切换到 primary 身份。

标准三步：

```go
resp, err := userClient.Auth.LinkExisting("alice", "password")
if err != nil {
    return err
}

// 1. 迁移业务数据：把 user_id = resp.SecondaryID 的记录改到 resp.PrimaryID
migrateUserRefs(resp.SecondaryID, resp.PrimaryID)

// 2. 切换到主账号身份
userClient.SetTokens(resp.Tokens.AccessToken, resp.Tokens.RefreshToken, resp.Tokens.ExpiresIn)

// 3. 清理墓碑
err = userClient.Auth.PurgeUser(resp.SecondaryID)
```

<details>
<summary>LinkExistingResponse 结构</summary>

```go
type LinkExistingResponse struct {
    Message     string    `json:"message"`
    PrimaryID   uint      `json:"primary_id"`   // 合并后保留的主账号 ID
    SecondaryID uint      `json:"secondary_id"` // 被合并掉的墓碑 ID
    Tokens      TokenPair `json:"tokens"`       // 主账号的新 Token
    User        struct {
        ID       uint   `json:"id"`
        Username string `json:"username"`
        Role     string `json:"role"`
    } `json:"user"`
}
```
</details>

---

#### GetCanonicalUser — 解析历史用户 ID

```go
func (a *AuthService) GetCanonicalUser(id uint) (*CanonicalUserResponse, error)
```

✓ `GET /auth/users/{id}/canonical`

把一个可能已被合并的用户 ID 解析到当前有效账号。业务库中存有历史 `user_id` 时可用它兜底：`Merged == true` 表示该 ID 已被合并，应改用 `CanonicalID`。ID 不存在返回 `404`。

```go
res, err := client.Auth.GetCanonicalUser(42)
if res.Merged {
    // 42 已被合并，实际账号是 res.CanonicalID
}
```

<details>
<summary>CanonicalUserResponse 结构</summary>

```go
type CanonicalUserResponse struct {
    RequestedID uint `json:"requested_id"`
    CanonicalID uint `json:"canonical_id"`
    Merged      bool `json:"merged"`
    User        struct {
        ID       uint   `json:"id"`
        Username string `json:"username"`
        Role     string `json:"role"`
        Status   string `json:"status"`
    } `json:"user"`
}
```
</details>

---

#### PurgeUser — 清理墓碑

```go
func (a *AuthService) PurgeUser(id uint) error
```

✓ `DELETE /auth/users/{id}/purge`

硬删除一个已被合并的墓碑用户。调用方必须是合并目标（primary）本人或 admin / root，否则返回 `403`；对未合并的活跃用户调用返回 `400`；ID 不存在返回 `404`。

```go
err := client.Auth.PurgeUser(secondaryID)
```

---

### StorageService — `client.Storage`

文件存储的全部操作。所有方法需要认证（✓），`Delete` 另有归属限制。multipart 表单字段名为 `file`。

#### Upload — 从本地路径上传

```go
func (s *StorageService) Upload(filePath string) (*File, error)
```

✓ `POST /api/storage/upload`

文件大小超过平台配置的 `storage.max_file_size` 时返回 `413`。

```go
file, err := client.Storage.Upload("/path/to/photo.jpg")
fmt.Printf("文件 ID: %d, 大小: %d bytes\n", file.ID, file.Size)
```

---

#### UploadReader — 从 io.Reader 上传

```go
func (s *StorageService) UploadReader(filename string, reader io.Reader) (*File, error)
```

✓ `POST /api/storage/upload`

适用于从网络流、内存缓冲等来源上传。服务端转发用户上传时可直接把 `multipart.FileHeader` 打开后的流传入，无需落盘。

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

✓ `GET /api/storage/files?page={page}&page_size={pageSize}`

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

✓ `GET /api/storage/files/{id}`

```go
file, err := client.Storage.GetMeta(42)
```

---

#### Download — 下载文件（流式）

```go
func (s *StorageService) Download(id uint) (io.ReadCloser, string, error)
```

✓ `GET /api/storage/files/{id}/download`

返回文件内容流和 `Content-Disposition` 响应头原文（格式为 `attachment; filename="<原始文件名>"`，不是解析后的文件名）。**调用者必须关闭返回的 ReadCloser**。

```go
body, contentDisp, err := client.Storage.Download(42)
if err != nil {
    return err
}
defer body.Close()
io.Copy(os.Stdout, body)
```

---

#### DownloadTo — 下载文件到本地路径

```go
func (s *StorageService) DownloadTo(id uint, destPath string) error
```

✓ `GET /api/storage/files/{id}/download`

```go
err := client.Storage.DownloadTo(42, "./downloads/photo.jpg")
```

---

#### Delete — 删除文件

```go
func (s *StorageService) Delete(id uint) error
```

✓ `DELETE /api/storage/files/{id}`

只能删除自己上传的文件；删除他人文件需持有 `storage` / `delete` 权限（默认策略仅授予 admin），否则返回 `403`；ID 不存在返回 `404`。

```go
err := client.Storage.Delete(42)
```

---

### ImageBedService — `client.ImageBed`

图床服务。与 Storage 的区别是有公开 / 私有可见性控制，图片可通过固定 URL 直接访问。multipart 表单字段名为 `image`。

> ⚠️ **权限要求**：图床的四个读写接口除了登录，还分别要求 `imagebed` 资源的 `upload` / `read` / `delete` / `update` 权限（✓ 权限）。开启 `permission.seed_defaults` 时，平台会给内置的 admin / user / editor 三个角色播种这四项；自定义角色需要管理员通过 `Permission.AddPolicy(role, "imagebed", "upload")` 等授予。Casbin 权限不足返回 `403`（`insufficient permissions`）；此外 `Delete` 和 `ToggleVisibility` 只能操作本人上传的图片，非本人且角色不是 admin 时同样返回 `403`。

#### Upload — 从本地路径上传图片

```go
func (s *ImageBedService) Upload(filePath string) (*Image, error)
```

✓ 权限 `POST /api/imagebed/upload`

允许的类型：jpeg / png / gif / webp / svg / bmp / ico，其他类型返回 `400`；超过平台配置的 `imagebed.max_file_size` 返回 `413`。

新上传的图片**默认 `is_public = true`**（服务端固定写入，上传请求不接受可见性参数），上传成功后任何人无需认证即可通过 `PublicURL(id)` 访问。需要私有的图片请在上传后立刻调用 `ToggleVisibility(id, false)`。

```go
img, err := client.ImageBed.Upload("./avatar.png")
fmt.Printf("图片 ID: %d, 公开: %v\n", img.ID, img.IsPublic)
```

---

#### UploadReader — 从 io.Reader 上传图片

```go
func (s *ImageBedService) UploadReader(filename string, reader io.Reader) (*Image, error)
```

✓ 权限 `POST /api/imagebed/upload`

`UploadReader` 会按 `filename` 的扩展名显式设置 multipart part 的 `Content-Type`，并内置了一张扩展名到 MIME 的兜底表（Alpine 等精简镜像没有 `/etc/mime.types`，标准库的 `mime.TypeByExtension` 会返回空）。**因此 `filename` 必须带 jpg / jpeg / png / gif / webp / svg / bmp / ico 之一的扩展名。** 扩展名错误但可识别时（如 `.txt`）会以对应的非图片 MIME 上传；扩展名缺失或无法识别时会以 `application/octet-stream` 上传，服务端会再按扩展名推断一次。两种情况服务端都会以 `400`（`unsupported image type`）拒绝。

```go
img, err := userClient.ImageBed.UploadReader(fileHeader.Filename, src)
```

<details>
<summary>Image 结构</summary>

```go
type Image struct {
    ID           uint      `json:"id"`
    Filename     string    `json:"filename"`
    OriginalName string    `json:"original_name"`
    Size         int64     `json:"size"`
    MimeType     string    `json:"mime_type"`
    StoragePath  string    `json:"storage_path"`
    UploaderID   uint      `json:"uploader_id"`
    IsPublic     bool      `json:"is_public"` // 上传后默认 true
    CreatedAt    time.Time `json:"created_at"`
    UpdatedAt    time.Time `json:"updated_at"`
}
```
</details>

---

#### List — 分页列出图片

```go
func (s *ImageBedService) List(page, pageSize int) (*ImageListResponse, error)
```

✓ 权限 `GET /api/imagebed/images?page={page}&page_size={pageSize}`

只返回当前用户自己上传的图片。

```go
list, err := client.ImageBed.List(1, 20)
```

<details>
<summary>ImageListResponse 结构</summary>

```go
type ImageListResponse struct {
    Data     []Image `json:"data"`
    Total    int64   `json:"total"`
    Page     int     `json:"page"`
    PageSize int     `json:"page_size"`
}
```
</details>

---

#### Delete — 删除图片

```go
func (s *ImageBedService) Delete(id uint) error
```

✓ 权限 `DELETE /api/imagebed/images/{id}`

只能删除自己上传的图片；角色为 admin（含 root）可删除任意图片，否则返回 `403`。

```go
err := client.ImageBed.Delete(7)
```

---

#### ToggleVisibility — 切换公开 / 私有

```go
func (s *ImageBedService) ToggleVisibility(id uint, isPublic bool) (*Image, error)
```

✓ 权限 `PATCH /api/imagebed/images/{id}/visibility`

只能修改自己上传的图片；角色为 admin（含 root）可修改任意图片，否则返回 `403`。

```go
img, err := client.ImageBed.ToggleVisibility(7, true) // 设为公开
```

---

#### PublicURL — 生成图片访问地址

```go
func (s *ImageBedService) PublicURL(id uint) string
```

**纯本地字符串拼接，不发起任何请求**，返回 `{BaseURL}/api/imagebed/{id}`。该地址对应平台的图片直出接口，鉴权按图片可见性决定：

- `IsPublic == true` 的图片无需认证即可访问；
- 私有图片需要在请求头携带任意有效的 `Authorization: Bearer` Token，否则返回 `401`。

> 拼接使用的是 Client 的 `BaseURL`。如果服务在容器内通过内网地址（如 `http://app:8080`）访问平台，生成的 URL 不能直接下发给浏览器，需要自行替换为对外域名。

```go
url := client.ImageBed.PublicURL(7)
// http://localhost:8080/api/imagebed/7
```

---

### PermissionService — `client.Permission`

RBAC 权限管理。不同方法的鉴权要求不同：模块注册与校验是服务间调用无需认证，注册表查询需登录，策略 / 角色 / 默认策略管理需 admin。

#### RegisterPermissions — 注册模块权限（服务间调用）

```go
func (p *PermissionService) RegisterPermissions(module string, resources []ResourceDef, grants ...RoleGrant) error
```

✗ `POST /api/permissions/registry`（平台配置了 `permission.service_token` 时需 `X-Service-Token`，见 `Config.ServiceToken`）

推荐每个业务模块在启动时调用，**幂等**，重复注册不会产生重复定义。

- `resources` 声明模块有哪些资源和动作，写入权限注册表，以 `{module}.{resource}` 为命名空间。
- `grants` 声明默认的角色授权。平台会以 `{module}.{resource}` 为 object 写入 Casbin 策略，与业务模块用 `CheckPermission` 校验时的写法一致，全新部署无需人工配权。admin 是超级用户，无需列出。

```go
err := client.Permission.RegisterPermissions("blog",
    []sdk.ResourceDef{
        {Resource: "article", Actions: []string{"create", "read", "update", "delete"}, Description: "博客文章"},
        {Resource: "comment", Actions: []string{"create", "read", "delete"}, Description: "评论"},
    },
    sdk.RoleGrant{Role: "user", Resource: "comment", Action: "create"},
    sdk.RoleGrant{Role: "user", Resource: "comment", Action: "read"},
)
```

> 注册本身不授予任何权限：admin 是超级用户无需策略，其他角色只拿到 `grants` 里声明的。`grants` 只能写 `{module}.` 前缀下的对象，无法触及平台自身（`storage`、`imagebed`）或其他模块的对象。

<details>
<summary>ResourceDef / RoleGrant 结构</summary>

```go
type ResourceDef struct {
    Resource    string   `json:"resource"`
    Actions     []string `json:"actions"`
    Description string   `json:"description,omitempty"`
}

type RoleGrant struct {
    Role     string `json:"role"`
    Resource string `json:"resource"` // 不带模块前缀，平台自动拼成 {module}.{resource}
    Action   string `json:"action"`
}
```
</details>

---

#### CheckPermission — 校验用户权限（服务间调用）

```go
func (p *PermissionService) CheckPermission(userID uint, object, action string) (bool, error)
```

✗ `POST /api/permissions/check`（平台配置了 `permission.service_token` 时需 `X-Service-Token`）

业务鉴权中间件的标准入口。判定顺序：

1. 用户不存在，返回 `404`（`*APIError`）；
2. 用户是 admin 或 root，直接返回 `true`；
3. 先匹配用户级策略，未命中再回退到角色级策略。

`object` 使用 `{module}.{resource}` 形式：

```go
allowed, err := client.Permission.CheckPermission(userID, "blog.comment", "create")
```

---

#### ListModules — 列出已注册模块

```go
func (p *PermissionService) ListModules() ([]string, error)
```

✓ `GET /api/permissions/registry`

任意登录用户可调。当 `permission.seed_defaults` 开启时（随附 `config.yaml` 默认开启），平台启动会以 `platform` 模块自注册 `user` / `role` / `policy` / `defaults` / `registry` 五组资源。

```go
modules, err := client.Permission.ListModules()
// ["platform", "blog", ...]
```

---

#### ListModulePermissions — 列出模块的权限定义

```go
func (p *PermissionService) ListModulePermissions(module string) ([]PermissionDef, error)
```

✓ `GET /api/permissions/registry/{module}`

```go
defs, err := client.Permission.ListModulePermissions("blog")
```

<details>
<summary>PermissionDef 结构</summary>

```go
type PermissionDef struct {
    ID          uint   `json:"id"`
    Module      string `json:"module"`
    Resource    string `json:"resource"`
    Action      string `json:"action"`
    Description string `json:"description"`
}
```
</details>

---

#### ListPolicies — 查询策略列表

```go
func (p *PermissionService) ListPolicies(role string) ([]Policy, error)
```

✓ Admin `GET /api/permissions/policies?role={role}`

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
    Object string `json:"object"` // 资源: 平台内置 article / storage 等，业务模块为 {module}.{resource}
    Action string `json:"action"` // 操作: create, read, update, delete, upload, manage 等
}
```
</details>

---

#### AddPolicy — 添加策略

```go
func (p *PermissionService) AddPolicy(role, object, action string) error
```

✓ Admin `POST /api/permissions/policies`

```go
err := client.Permission.AddPolicy("user", "imagebed", "upload")
```

---

#### RemovePolicy — 删除策略

```go
func (p *PermissionService) RemovePolicy(role, object, action string) error
```

✓ Admin `DELETE /api/permissions/policies`

```go
err := client.Permission.RemovePolicy("user", "imagebed", "upload")
```

---

#### ListUserRoles — 查询用户角色

```go
func (p *PermissionService) ListUserRoles(userID uint) ([]string, error)
```

✓ Admin `GET /api/permissions/roles/{userID}`

```go
roles, err := client.Permission.ListUserRoles(1)
// roles = ["admin"]
```

---

#### AssignRole — 分配角色

```go
func (p *PermissionService) AssignRole(userID uint, role string) error
```

✓ Admin `POST /api/permissions/roles`

```go
err := client.Permission.AssignRole(5, "editor")
```

---

#### RemoveRole — 移除角色

```go
func (p *PermissionService) RemoveRole(userID uint, role string) error
```

✓ Admin `DELETE /api/permissions/roles`

```go
err := client.Permission.RemoveRole(5, "editor")
```

---

#### GetDefaultPolicies — 查询角色的默认策略

```go
func (p *PermissionService) GetDefaultPolicies(role string) ([]DefaultPolicy, error)
```

✓ Admin `GET /api/permissions/defaults/{role}`

默认策略是新用户注册时自动套用的策略模板。

```go
defaults, err := client.Permission.GetDefaultPolicies("user")
```

<details>
<summary>DefaultPolicy 结构</summary>

```go
type DefaultPolicy struct {
    ID     uint   `json:"id"`
    Role   string `json:"role"`
    Object string `json:"object"` // 例如 "blog.comment"
    Action string `json:"action"`
}
```
</details>

---

#### SetDefaultPolicies — 设置角色的默认策略

```go
func (p *PermissionService) SetDefaultPolicies(role string, policies []Policy) error
```

✓ Admin `PUT /api/permissions/defaults/{role}`

**整体替换**语义，不是追加：先清空该角色的全部默认策略，再写入 `policies`；传 `[]sdk.Policy{}`（非 nil 的空切片）即清空。注意传 `nil` 会被序列化为 `"policies": null`，服务端校验失败返回 `400`。每一项的 `Role` 字段会被平台覆盖为路径中的 `role`，可以不填。

```go
err := client.Permission.SetDefaultPolicies("user", []sdk.Policy{
    {Object: "blog.comment", Action: "create"},
    {Object: "blog.comment", Action: "read"},
})
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
    Message    string // 错误消息，取响应体的 error 字段，缺失时回落到 HTTP 状态文本
}
```

网络层和序列化层的错误则以 `sdk: <阶段>: <原因>` 形式包装原始 error，可用 `errors.Unwrap` 取出。

例外：需要认证的方法在 Access Token 即将过期且 Client 持有 Refresh Token 时，会先自动调用 `/auth/refresh`。若该刷新请求失败（Refresh Token 已失效或被吊销返回 `401`，或网络错误），错误会被包装为 `sdk: auto-refresh failed: <原始错误>`，而不是直接返回 `*APIError`。请始终用 `errors.As` 取出 `*APIError`，不要做 `err.(*sdk.APIError)` 类型断言。

常见状态码：

| 状态码 | 典型含义 |
|--------|----------|
| `400` | 参数缺失或不合法、不支持的 provider、`redirect_uri` 不在白名单、不支持的图片类型、解绑未绑定的 OAuth 账号 |
| `401` | 未携带 Token、Token 无效或过期、凭据错误、服务间接口缺少或错误的 `X-Service-Token` |
| `403` | 角色或权限不足、用户被禁用、平台已关闭注册 |
| `404` | 资源或用户不存在、OAuth 未配置 |
| `409` | 用户名已存在、账号已被合并 |
| `410` | 第三方 Token 未存储，需重新授权 |
| `413` | 文件超过大小限制 |
| `503` | 平台未配置 OAuth 回跳白名单 |

> `Auth.Verify()` 对空 / 无效 Token 返回的是 `*APIError`（`400` / `401` / `403`），而不是 `Valid == false` 的响应，见该方法说明。

---

## 最佳实践

### 微服务集成模式（推荐）

```go
package main

import (
    "log"
    "os"

    "github.com/begonia599/myplatform/sdk"
    "github.com/gin-gonic/gin"
)

// 全局客户端 — 服务启动时创建一次，只用于服务间调用和派生 WithToken
var platform *sdk.Client

func main() {
    platform = sdk.New(&sdk.Config{
        BaseURL:      "http://localhost:8080",
        ServiceToken: os.Getenv("PLATFORM_SERVICE_TOKEN"), // 与平台 permission.service_token 一致
    })

    // 启动时注册本模块的权限与默认授权（幂等）
    if err := platform.Permission.RegisterPermissions("drive",
        []sdk.ResourceDef{
            {Resource: "file", Actions: []string{"read", "write"}, Description: "网盘文件"},
        },
        sdk.RoleGrant{Role: "user", Resource: "file", Action: "read"},
    ); err != nil {
        log.Fatal(err)
    }

    r := gin.Default()
    r.Use(AuthMiddleware())
    r.GET("/my-files", RequirePermission("drive.file", "read"), handleMyFiles)
    r.Run(":8081")
}

// 认证中间件 — 验证用户 Token
func AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        token := extractBearerToken(c)
        result, err := platform.Auth.Verify(token)
        if err != nil {
            c.AbortWithStatusJSON(401, gin.H{"error": "unauthorized"})
            return
        }
        c.Set("user", result.User)
        c.Set("token", token)
        c.Next()
    }
}

// 权限中间件 — 服务间校验，无需认证
func RequirePermission(object, action string) gin.HandlerFunc {
    return func(c *gin.Context) {
        user := c.MustGet("user").(sdk.VerifyUser)
        allowed, err := platform.Permission.CheckPermission(user.ID, object, action)
        if err != nil || !allowed {
            c.AbortWithStatusJSON(403, gin.H{"error": "forbidden"})
            return
        }
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

### OAuth 登录接入

```go
// 1. 前端请求登录，后端返回第三方授权地址
func handleOAuthLogin(c *gin.Context) {
    resp, err := platform.Auth.OAuthAuthorize(c.Param("provider"), "https://app.example.com/oauth/callback")
    if err != nil {
        c.JSON(502, gin.H{"error": err.Error()})
        return
    }
    c.JSON(200, gin.H{"auth_url": resp.AuthURL})
}

// 2. 前端在回跳页拿到 ?exchange_code=... 后交给后端换取 Token
func handleOAuthExchange(c *gin.Context) {
    var req struct {
        ExchangeCode string `json:"exchange_code" binding:"required"`
    }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": "exchange_code is required"})
        return
    }
    tokens, err := platform.Auth.OAuthExchange(req.ExchangeCode)
    if err != nil {
        c.JSON(401, gin.H{"error": err.Error()})
        return
    }
    c.JSON(200, tokens)
}
```

### 账号绑定与合并

- 已登录用户想加绑一个第三方账号：用该用户的 `WithToken` 客户端调用 `OAuthBindAuthorize`，回跳后读取 `bind_result`。
- 用 OAuth 新登录的用户想认领已有的本地账号：调用 `LinkExisting`，然后按「迁移业务数据、切换身份、`PurgeUser` 清理墓碑」三步完成。
- 业务库里存有历史 `user_id`，不确定是否已被合并：用 `GetCanonicalUser` 解析到当前有效账号。

### 要点总结

| 场景 | 方法 |
|------|------|
| 服务间 Token 验证 | `client.Auth.Verify(token)` — 无需认证 |
| 服务间权限校验 | `client.Permission.CheckPermission(userID, object, action)` — 无需认证 |
| 启动时声明模块权限 | `client.Permission.RegisterPermissions(module, resources, grants...)` — 无需认证、幂等 |
| 代理用户请求 | `client.WithToken(token)` — 轻量级，不自动刷新 |
| 服务自身操作 | `client.Auth.Login()` — 自动管理 Token |
| 恢复已有 Token | `client.SetTokens(access, refresh, expiresIn)` |
| 代表用户调用第三方 API | `client.Auth.GetOAuthToken(provider)` |

---

## REST API 路由速查表

认证列含义见「鉴权层级」：✗ 无需认证，✓ 需登录，✓ Admin 需 admin 角色，✓ 权限 需登录且持有对应 Casbin 权限（以 `object:action` 简写）。

### Auth

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
| PUT | `/auth/password` | ✓ | `Auth.ChangePassword()` |
| GET | `/auth/oauth/:provider` | ✗ | `Auth.OAuthAuthorize()` |
| POST | `/auth/oauth/exchange` | ✗ | `Auth.OAuthExchange()` |
| GET | `/auth/oauth/:provider/bind` | ✓ | `Auth.OAuthBindAuthorize()` |
| GET | `/auth/oauth/accounts` | ✓ | `Auth.GetOAuthAccounts()` |
| GET | `/auth/oauth/accounts/:provider/token` | ✓ | `Auth.GetOAuthToken()` |
| DELETE | `/auth/oauth/accounts/:provider` | ✓ | `Auth.UnlinkOAuth()` |
| POST | `/auth/oauth/link-existing` | ✓ | `Auth.LinkExisting()` |
| GET | `/auth/users/:id/canonical` | ✓ | `Auth.GetCanonicalUser()` |
| DELETE | `/auth/users/:id/purge` | ✓ | `Auth.PurgeUser()` |

### Storage

| 方法 | 路径 | 认证 | SDK 方法 |
|------|------|------|----------|
| POST | `/api/storage/upload` | ✓ | `Storage.Upload()` / `Storage.UploadReader()` |
| GET | `/api/storage/files` | ✓ | `Storage.List()` |
| GET | `/api/storage/files/:id` | ✓ | `Storage.GetMeta()` |
| GET | `/api/storage/files/:id/download` | ✓ | `Storage.Download()` / `Storage.DownloadTo()` |
| DELETE | `/api/storage/files/:id` | ✓ 本人文件；他人文件需 ✓ 权限 `storage:delete` | `Storage.Delete()` |

### ImageBed

| 方法 | 路径 | 认证 | SDK 方法 |
|------|------|------|----------|
| POST | `/api/imagebed/upload` | ✓ 权限 `imagebed:upload` | `ImageBed.Upload()` / `ImageBed.UploadReader()` |
| GET | `/api/imagebed/images` | ✓ 权限 `imagebed:read` | `ImageBed.List()` |
| DELETE | `/api/imagebed/images/:id` | ✓ 权限 `imagebed:delete`，仅本人图片（admin 除外） | `ImageBed.Delete()` |
| PATCH | `/api/imagebed/images/:id/visibility` | ✓ 权限 `imagebed:update`，仅本人图片（admin 除外） | `ImageBed.ToggleVisibility()` |
| GET | `/api/imagebed/:id` | 公开图片 ✗，私有图片 ✓ | `ImageBed.PublicURL()`（仅拼接地址） |

### Permission

| 方法 | 路径 | 认证 | SDK 方法 |
|------|------|------|----------|
| POST | `/api/permissions/registry` | ✗（可配置 `X-Service-Token`） | `Permission.RegisterPermissions()` |
| POST | `/api/permissions/check` | ✗（可配置 `X-Service-Token`） | `Permission.CheckPermission()` |
| GET | `/api/permissions/registry` | ✓ | `Permission.ListModules()` |
| GET | `/api/permissions/registry/:module` | ✓ | `Permission.ListModulePermissions()` |
| GET | `/api/permissions/policies` | ✓ Admin | `Permission.ListPolicies()` |
| POST | `/api/permissions/policies` | ✓ Admin | `Permission.AddPolicy()` |
| DELETE | `/api/permissions/policies` | ✓ Admin | `Permission.RemovePolicy()` |
| GET | `/api/permissions/roles/:user_id` | ✓ Admin | `Permission.ListUserRoles()` |
| POST | `/api/permissions/roles` | ✓ Admin | `Permission.AssignRole()` |
| DELETE | `/api/permissions/roles` | ✓ Admin | `Permission.RemoveRole()` |
| GET | `/api/permissions/defaults/:role` | ✓ Admin | `Permission.GetDefaultPolicies()` |
| PUT | `/api/permissions/defaults/:role` | ✓ Admin | `Permission.SetDefaultPolicies()` |
