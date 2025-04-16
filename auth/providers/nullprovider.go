package providers

import (
	"encoding/json"
	"fmt"
)

type NullAuthProvider struct {
	AuthProvider
}

func NewNullAuthProvider(config json.RawMessage) AuthProvider {
	return &NullAuthProvider{}
}

func (a *NullAuthProvider) AuthenticateUser(username, password string) bool {
	return true
}

func (a *NullAuthProvider) AuthenticateWithAppPassword(username, password string) bool {
	return true
}

func (a *NullAuthProvider) AddUser(username, password, role string) error {
	return nil
}

func (a *NullAuthProvider) RemoveUser(username string) error {
	return nil
}

func (a *NullAuthProvider) GetUsers() ([]string, error) {
	users := make([]string, 0)
	return users, nil
}

func (a *NullAuthProvider) ChangePassword(username, password string) error {
	return nil
}

func (a *NullAuthProvider) DropUsers() error {
	return nil
}

func (a *NullAuthProvider) LoadUsers() error {
	return fmt.Errorf("not implemented")
}

func (a *NullAuthProvider) GetRole(username string) (string, error) {
	if username == "admin" {
		return "admin", nil
	}
	return "viewer", nil
}

func (a *NullAuthProvider) GetUser(username string) (UserView, error) {
	return UserView{}, fmt.Errorf("not implemented")
}

func (a *NullAuthProvider) SetRole(username, role string) error {
	return fmt.Errorf("not implemented")
}

func (a *NullAuthProvider) AddAppPassword(username, password string, expire int) error {
	return nil
}

func (a *NullAuthProvider) RevokeAppPassword(username, id string) error {
	return nil
}

func (a *NullAuthProvider) ListAppPasswordsIds(username string) ([]string, error) {
	return []string{}, nil
}

func (a *NullAuthProvider) CleanUpRevokedExpiredAppPasswords() error {
	return nil
}
