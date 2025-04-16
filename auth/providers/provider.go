package providers

import (
	"encoding/json"
	"fmt"
)

var authProvider AuthProvider

func SetAuthProviderFactory(factory AuthProviderFactory, config json.RawMessage) {
	authProvider = factory(config)
}

func GetAuthProvider() AuthProvider {
	return authProvider
}

func AuthenticateUser(username, password string) *UserView {
	user := authProvider.AuthenticateUser(username, password)
	if user == nil {
		return authProvider.AuthenticateWithAppPassword(username, password)
	}
	return user
}

func AddUser(username, password, role string) error {
	hash, err := HashPassword(password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}
	return authProvider.AddUser(username, hash, role)
}

func RemoveUser(username string) error {
	return authProvider.RemoveUser(username)
}

func GetUsers() ([]string, error) {
	return authProvider.GetUsers()
}

func ChangePassword(username, password string) error {
	hash, err := HashPassword(password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}
	return authProvider.ChangePassword(username, hash)
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
		SetAuthProviderFactory(NewFileAuthProvider, config)
	case "memory":
		SetAuthProviderFactory(NewMemoryAuthProvider, config)
	default:
		return fmt.Errorf("unsupported auth provider")
	}
	return nil
}

func LoadUsers() error {
	return authProvider.LoadUsers()
}

func GetUser(username string) (UserView, error) {
	return authProvider.GetUser(username)
}

func SetRole(username, role string) error {
	return authProvider.SetRole(username, role)
}

func GenerateAppPassword(name string, username, role string, expire int) (string, string, error) {
	pw, err := GenerateRandomPassword()

	if err != nil {
		return "", "", err
	}

	hash, err := HashPassword(pw)
	if err != nil {
		return "", "", fmt.Errorf("failed to hash password: %v", err)
	}

	id, err := authProvider.AddAppPassword(username, hash, role, expire)
	if err != nil {
		return "", "", err
	}

	return id, pw, nil
}

func RevokeAppPassword(username, id string) error {
	return authProvider.RevokeAppPassword(username, id)
}

func ListAppPasswordsIds(username string) ([]string, error) {
	return authProvider.ListAppPasswordsIds(username)
}

func CleanUpRevokedExpiredAppPasswords() error {
	return authProvider.CleanUpRevokedExpiredAppPasswords()
}
