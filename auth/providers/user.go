package providers

import (
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
	Revoked   bool      `json:"revoked"`
}

type AppPasswordView struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
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
