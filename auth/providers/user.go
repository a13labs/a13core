package providers

import (
	"time"
)

type User struct {
	Username     string        `json:"username"`
	Password     string        `json:"password"`
	Role         string        `json:"role"`
	AppPasswords []AppPassword `json:"app_passwords,omitempty"`
}

type UserView struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

type Users struct {
	Users []User `json:"users"`
}

type AppPassword struct {
	ID        string    // Unique identifier for the app password
	Hash      string    // Hashed app password
	CreatedAt time.Time // Timestamp of creation
	ExpiresAt time.Time // Optional expiration time
	Revoked   bool      // Whether the password is revoked
}
