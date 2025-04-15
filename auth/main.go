package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/a13labs/a13core/auth/jwt"
	"github.com/a13labs/a13core/auth/providers"
)

type AuthConfig struct {
	Provider       string          `json:"provider"`
	SecretKey      string          `json:"secret_key"`
	ExpirationTime int             `json:"expiration_time,omitempty"`
	Settings       json.RawMessage `json:"settings"`
}

var authConfig AuthConfig

func InitializeAuth(data json.RawMessage) error {

	err := json.Unmarshal(data, &authConfig)
	if err != nil {
		return err
	}

	if authConfig.Provider == "" {
		return errors.New("auth provider is required")
	}

	if len(authConfig.SecretKey) == 0 {
		return errors.New("secret key is required")
	}

	if authConfig.ExpirationTime == 0 {
		authConfig.ExpirationTime = 24
	}

	return providers.InitializeAuthProvider(authConfig.Provider, authConfig.Settings)
}

func GetRole(username string) (string, error) {
	return providers.GetRole(username)
}

func CheckCredentials(username, password string) bool {
	return providers.AuthenticateUser(username, password)
}

func AddUser(username, password string) error {
	return providers.AddUser(username, password)
}

func RemoveUser(username string) error {
	return providers.RemoveUser(username)
}

func GetUsers() ([]string, error) {
	return providers.GetUsers()
}

func ChangePassword(username, password string) error {
	return providers.ChangePassword(username, password)
}

func DropUsers() error {
	return providers.DropUsers()
}

func GetUser(username string) (providers.UserView, error) {
	return providers.GetUser(username)
}

func SetRole(username, role string) error {
	return providers.SetRole(username, role)
}

func CreateToken(userId, password string) (string, error) {

	if CheckCredentials(userId, password) {
		role, err := GetRole(userId)
		if err != nil || role == "" {
			role = "viewer"
		}
		return jwt.Create(userId, role, authConfig.ExpirationTime, authConfig.SecretKey)
	}
	return "", fmt.Errorf("invalid credentials")
}

func VerifyUserToken(userId, token string) bool {
	claims, err := jwt.Unmap(token, authConfig.SecretKey)
	if err != nil {
		return false
	}
	if sub, ok := claims["sub"].(string); ok {
		if sub == userId {
			return true
		}
	}
	return false
}

func VerifyToken(token string) bool {
	_, err := jwt.Unmap(token, authConfig.SecretKey)
	return err == nil
}

func GetRoleFromToken(token string) (string, error) {
	claims, err := jwt.Unmap(token, authConfig.SecretKey)
	if err != nil {
		return "", err
	}
	if role, ok := claims["role"].(string); ok {
		return role, nil
	}
	return "", fmt.Errorf("role not found")
}

func GetUserFromToken(token string) (string, error) {
	claims, err := jwt.Unmap(token, authConfig.SecretKey)
	if err != nil {
		return "", err
	}
	if sub, ok := claims["sub"].(string); ok {
		return sub, nil
	}
	return "", fmt.Errorf("user id not found")
}

func TokenExpired(token string) bool {
	claims, err := jwt.Unmap(token, authConfig.SecretKey)
	if err != nil {
		return true
	}
	if exp, ok := claims["exp"].(int64); ok {
		if int64(exp) == 0 || exp < time.Now().Unix() {
			return false
		}
	}
	return true
}

func GenerateAppToken(name string, username, role string, expire int) (string, error) {
	return providers.GenerateAppToken(name, username, role, expire, authConfig.SecretKey)
}

func ValidateAppToken(token string) (string, error) {
	return providers.ValidateAppToken(token, authConfig.SecretKey)
}
