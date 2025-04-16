package providers

import (
	"encoding/json"
	"fmt"
)

type AuthProvider interface {
	AuthenticateUser(username, password string) bool
	AuthenticateWithAppPassword(username, password string) bool
	AddUser(username, hash, role string) error
	RemoveUser(username string) error
	GetRole(username string) (string, error)
	SetRole(username, role string) error
	GetUsers() ([]string, error)
	ChangePassword(username, hash string) error
	DropUsers() error
	LoadUsers() error
	GetUser(username string) (UserView, error)
	AddAppPassword(username, hash string, expire int) error
	RevokeAppPassword(username, id string) error
	ListAppPasswordsIds(username string) ([]string, error)
	CleanUpRevokedExpiredAppPasswords() error
}

type AuthProviderFactory func(config json.RawMessage) AuthProvider

var authProvider AuthProvider

func SetAuthProviderFactory(factory AuthProviderFactory, config json.RawMessage) {
	authProvider = factory(config)
}

func GetAuthProvider() AuthProvider {
	return authProvider
}

func AuthenticateUser(username, password string) bool {
	valid := authProvider.AuthenticateUser(username, password)
	if !valid {
		return authProvider.AuthenticateWithAppPassword(username, password)
	}
	return valid
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

func GenerateAppPassword(name string, username, role string, expire int) (string, error) {
	pw, hashedPassword, err := GenerateRandomPassword()

	if err != nil {
		return "", err
	}
	err = authProvider.AddAppPassword(username, hashedPassword, expire)
	if err != nil {
		return "", err
	}

	return pw, nil
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
