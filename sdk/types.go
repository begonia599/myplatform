package sdk

import "time"

// ---------- Auth ----------

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
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

type MeResponse struct {
	User    User        `json:"user"`
	Profile UserProfile `json:"profile"`
}

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

type RegisterResponse struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

// ---------- Storage ----------

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

type FileListResponse struct {
	Data     []File `json:"data"`
	Total    int64  `json:"total"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}

// ---------- Permission ----------

type Policy struct {
	Role   string `json:"role"`
	Object string `json:"object"`
	Action string `json:"action"`
}

type PolicyListResponse struct {
	Policies []Policy `json:"policies"`
}

type UserRolesResponse struct {
	UserID uint     `json:"user_id"`
	Roles  []string `json:"roles"`
}

// ---------- Permission Registry ----------

type ResourceDef struct {
	Resource    string   `json:"resource"`
	Actions     []string `json:"actions"`
	Description string   `json:"description,omitempty"`
}

type PermissionDef struct {
	ID          uint   `json:"id"`
	Module      string `json:"module"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

type ModulesResponse struct {
	Modules []string `json:"modules"`
}

type ModulePermissionsResponse struct {
	Module      string          `json:"module"`
	Permissions []PermissionDef `json:"permissions"`
}

// ---------- Default Role Policies ----------

type DefaultPolicy struct {
	ID     uint   `json:"id"`
	Role   string `json:"role"`
	Object string `json:"object"`
	Action string `json:"action"`
}

type DefaultPoliciesResponse struct {
	Role     string          `json:"role"`
	Policies []DefaultPolicy `json:"policies"`
}

// ---------- ImageBed ----------

type Image struct {
	ID           uint      `json:"id"`
	Filename     string    `json:"filename"`
	OriginalName string    `json:"original_name"`
	Size         int64     `json:"size"`
	MimeType     string    `json:"mime_type"`
	StoragePath  string    `json:"storage_path"`
	UploaderID   uint      `json:"uploader_id"`
	IsPublic     bool      `json:"is_public"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type ImageListResponse struct {
	Data     []Image `json:"data"`
	Total    int64   `json:"total"`
	Page     int     `json:"page"`
	PageSize int     `json:"page_size"`
}

