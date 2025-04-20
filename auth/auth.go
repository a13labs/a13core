package auth

import (
	"encoding/json"
	"errors"

	"github.com/a13labs/a13core/auth/providers"
	providerTypes "github.com/a13labs/a13core/auth/providers/types"
)

type AuthConfig struct {
	Provider       string          `json:"provider"`
	SecretKey      string          `json:"secret_key"`
	ExpirationTime int             `json:"expiration_time,omitempty"`
	Settings       json.RawMessage `json:"settings"`
}

var authConfig AuthConfig
var authLayer *providers.AuthLayer

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

	authLayer, err = providers.FromConfig(authConfig.Provider, authConfig.Settings)
	if err != nil {
		return err
	}

	return nil
}

func GetRole(username string) (string, error) {
	return authLayer.GetRole(username)
}

func CheckCredentials(username, password string) *providerTypes.UserView {
	return authLayer.AuthenticateUser(username, password)
}

func AddUser(username, password, role string) error {
	return authLayer.AddUser(username, password, role)
}

func RemoveUser(username string) error {
	return authLayer.RemoveUser(username)
}

func GetUsers() ([]providerTypes.UserView, error) {
	return authLayer.GetUsers()
}

func ChangePassword(username, password string) error {
	return authLayer.ChangePassword(username, password)
}

func DropUsers() error {
	return authLayer.DropUsers()
}

func GetUser(username string) (providerTypes.UserView, error) {
	return authLayer.GetUser(username)
}

func SetRole(username, role string) error {
	return authLayer.SetRole(username, role)
}

func GenerateAppPassword(name, username, role string, expire int) (string, string, error) {
	return authLayer.GenerateAppPassword(name, username, role, expire)
}

func RevokeAppPassword(username, id string) error {
	return authLayer.RevokeAppPassword(username, id)
}

func GetAppPasswords(username string) ([]providerTypes.AppPasswordView, error) {
	return authLayer.GetAppPasswords(username)
}

func CleanUpRevokedExpiredAppPasswords() error {
	return authLayer.CleanUpRevokedExpiredAppPasswords()
}

func SupportUserManagement() bool {
	return authLayer.SupportUserManagement()
}
