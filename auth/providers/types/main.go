package providers

import (
	"encoding/json"
	"time"
)

type User struct {
	Username     string        `json:"username"`
	Hash         string        `json:"hash"`
	Role         string        `json:"role"`
	AppPasswords []AppPassword `json:"app_passwords,omitempty"`
}

type AppPassword struct {
	ID        string    `json:"id"`
	Hash      string    `json:"hash"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Role      string    `json:"role"`
	Revoked   bool      `json:"revoked"`
}

type AppPasswordView struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Role      string    `json:"role"`
	Revoked   bool      `json:"revoked"`
}

type UserView struct {
	Username     string            `json:"username"`
	Role         string            `json:"role"`
	AppPasswords []AppPasswordView `json:"app_passwords,omitempty"`
}

type Users struct {
	Users []User `json:"users"`
}

type AuthProvider interface {
	Authenticate(username, password string) *UserView
}

type UserManagement interface {
	GetUser(username string) (UserView, error)
	GetRole(username string) (string, error)
	AddUser(username, password, role string) error
	RemoveUser(username string) error
	ChangePassword(username, password string) error
	SetRole(username, role string) error
	GetUsers() ([]UserView, error)
	DropUsers() error
	LoadUsers() error
	AddAppPassword(username, password, role string, expire int) (string, error)
	RevokeAppPassword(username, id string) error
	GetAppPasswords(username string) ([]AppPasswordView, error)
	CleanUpRevokedExpiredAppPasswords() error
}

type AuthProviderFactory func(config json.RawMessage) AuthProvider
type UserManagementFactory func(config json.RawMessage) UserManagement
