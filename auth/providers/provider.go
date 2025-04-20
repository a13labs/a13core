package providers

import (
	"encoding/json"
	"fmt"

	fileProvider "github.com/a13labs/a13core/auth/providers/file"
	"github.com/a13labs/a13core/auth/providers/internal"
	ldapProvider "github.com/a13labs/a13core/auth/providers/ldap"
	memProvider "github.com/a13labs/a13core/auth/providers/memory"
	providerTypes "github.com/a13labs/a13core/auth/providers/types"
)

var authProvider providerTypes.AuthProvider

func SetAuthProvider(factory providerTypes.AuthProviderFactory, config json.RawMessage) {
	authProvider = factory(config)
}

func GetAuthProvider() providerTypes.AuthProvider {
	return authProvider
}

func AuthenticateUser(username, password string) *providerTypes.UserView {
	user := authProvider.AuthenticateUser(username, password)
	if user == nil {
		return authProvider.AuthenticateWithAppPassword(username, password)
	}
	return user
}

func AddUser(username, password, role string) error {
	return authProvider.AddUser(username, password, role)
}

func RemoveUser(username string) error {
	return authProvider.RemoveUser(username)
}

func GetUsers() ([]providerTypes.UserView, error) {
	return authProvider.GetUsers()
}

func ChangePassword(username, password string) error {
	return authProvider.ChangePassword(username, password)
}

func DropUsers() error {
	return authProvider.DropUsers()
}

func GetRole(username string) (string, error) {
	return authProvider.GetRole(username)
}

func InitializeAuthProvider(provider string, config json.RawMessage) error {
	switch provider {
	case "file":
		SetAuthProvider(fileProvider.FromConfig, config)
	case "memory":
		SetAuthProvider(memProvider.FromConfig, config)
	case "ldap":
		SetAuthProvider(ldapProvider.FromConfig, config)
	default:
		return fmt.Errorf("unsupported auth provider")
	}
	return nil
}

func LoadUsers() error {
	return authProvider.LoadUsers()
}

func GetUser(username string) (providerTypes.UserView, error) {
	return authProvider.GetUser(username)
}

func SetRole(username, role string) error {
	return authProvider.SetRole(username, role)
}

func GenerateAppPassword(name string, username, role string, expire int) (string, string, error) {
	password, err := internal.GenerateRandomPassword()

	if err != nil {
		return "", "", err
	}

	id, err := authProvider.AddAppPassword(username, password, role, expire)
	if err != nil {
		return "", "", err
	}

	return id, password, nil
}

func RevokeAppPassword(username, id string) error {
	return authProvider.RevokeAppPassword(username, id)
}

func GetAppPasswords(username string) ([]providerTypes.AppPasswordView, error) {
	return authProvider.GetAppPasswords(username)
}

func CleanUpRevokedExpiredAppPasswords() error {
	return authProvider.CleanUpRevokedExpiredAppPasswords()
}
