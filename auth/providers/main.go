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

type AuthLayer struct {
	authProvider   providerTypes.AuthProvider
	userManagement providerTypes.UserManagement
}

func FromConfig(provider string, config json.RawMessage) (*AuthLayer, error) {
	switch provider {
	case "file":
		authProvider := fileProvider.FromConfig(config)
		userManagement, _ := authProvider.(providerTypes.UserManagement)

		return &AuthLayer{
			authProvider:   authProvider,
			userManagement: userManagement,
		}, nil
	case "memory":
		authProvider := memProvider.FromConfig(config)
		userManagement, _ := authProvider.(providerTypes.UserManagement)

		return &AuthLayer{
			authProvider:   authProvider,
			userManagement: userManagement,
		}, nil
	case "ldap":
		authProvider := ldapProvider.FromConfig(config)
		userManagement, _ := authProvider.(providerTypes.UserManagement)

		return &AuthLayer{
			authProvider:   authProvider,
			userManagement: userManagement,
		}, nil
	default:
		return nil, fmt.Errorf("unknown auth provider: %s", provider)
	}
}

func (l *AuthLayer) AuthenticateUser(username, password string) *providerTypes.UserView {
	user := l.authProvider.AuthenticateUser(username, password)
	if user == nil {
		return l.authProvider.AuthenticateWithAppPassword(username, password)
	}
	return user
}

func (l *AuthLayer) AddUser(username, password, role string) error {
	if l.userManagement == nil {
		return fmt.Errorf("user management is not supported by the provider")
	}
	return l.userManagement.AddUser(username, password, role)
}

func (l *AuthLayer) RemoveUser(username string) error {
	if l.userManagement == nil {
		return fmt.Errorf("user management is not supported by the provider")
	}
	return l.userManagement.RemoveUser(username)
}

func (l *AuthLayer) GetUsers() ([]providerTypes.UserView, error) {
	if l.userManagement == nil {
		return nil, fmt.Errorf("user management is not supported by the provider")
	}
	return l.userManagement.GetUsers()
}

func (l *AuthLayer) ChangePassword(username, password string) error {
	if l.userManagement == nil {
		return fmt.Errorf("user management is not supported by the provider")
	}
	return l.userManagement.ChangePassword(username, password)
}

func (l *AuthLayer) DropUsers() error {
	if l.userManagement == nil {
		return fmt.Errorf("user management is not supported by the provider")
	}
	return l.userManagement.DropUsers()
}

func (l *AuthLayer) GetRole(username string) (string, error) {
	if l.userManagement == nil {
		return "", fmt.Errorf("user management is not supported by the provider")
	}
	return l.userManagement.GetRole(username)
}

func (l *AuthLayer) LoadUsers() error {
	if l.userManagement == nil {
		return fmt.Errorf("user management is not supported by the provider")
	}
	return l.userManagement.LoadUsers()
}

func (l *AuthLayer) GetUser(username string) (providerTypes.UserView, error) {
	if l.userManagement == nil {
		return providerTypes.UserView{}, fmt.Errorf("user management is not supported by the provider")
	}
	return l.userManagement.GetUser(username)
}

func (l *AuthLayer) SetRole(username, role string) error {
	if l.userManagement == nil {
		return fmt.Errorf("user management is not supported by the provider")
	}
	return l.userManagement.SetRole(username, role)
}

func (l *AuthLayer) GenerateAppPassword(name string, username, role string, expire int) (string, string, error) {
	if l.userManagement == nil {
		return "", "", fmt.Errorf("user management is not supported by the provider")
	}
	password, err := internal.GenerateRandomPassword()

	if err != nil {
		return "", "", err
	}

	id, err := l.userManagement.AddAppPassword(username, password, role, expire)
	if err != nil {
		return "", "", err
	}

	return id, password, nil
}

func (l *AuthLayer) RevokeAppPassword(username, id string) error {
	if l.userManagement == nil {
		return fmt.Errorf("user management is not supported by the provider")
	}
	return l.userManagement.RevokeAppPassword(username, id)
}

func (l *AuthLayer) GetAppPasswords(username string) ([]providerTypes.AppPasswordView, error) {
	if l.userManagement == nil {
		return nil, fmt.Errorf("user management is not supported by the provider")
	}
	return l.userManagement.GetAppPasswords(username)
}

func (l *AuthLayer) CleanUpRevokedExpiredAppPasswords() error {
	if l.userManagement == nil {
		return fmt.Errorf("user management is not supported by the provider")
	}
	return l.userManagement.CleanUpRevokedExpiredAppPasswords()
}

func (l *AuthLayer) SupportUserManagement() bool {
	return l.userManagement != nil
}
