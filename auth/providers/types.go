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
	AuthenticateUser(username, password string) *UserView
	AuthenticateWithAppPassword(username, password string) *UserView
	AddUser(username, hash, role string) error
	RemoveUser(username string) error
	GetRole(username string) (string, error)
	SetRole(username, role string) error
	GetUsers() ([]string, error)
	ChangePassword(username, hash string) error
	DropUsers() error
	LoadUsers() error
	GetUser(username string) (UserView, error)
	AddAppPassword(username, hash, role string, expire int) (string, error)
	RevokeAppPassword(username, id string) error
	ListAppPasswordsIds(username string) ([]string, error)
	CleanUpRevokedExpiredAppPasswords() error
}

type AuthProviderFactory func(config json.RawMessage) AuthProvider
