package providers

import (
	"encoding/json"
	"fmt"
	"time"
)

type MemoryAuthProvide struct {
	AuthProvider
	users map[string]*User
}

func NewMemoryAuthProvider(config json.RawMessage) AuthProvider {
	return &MemoryAuthProvide{
		users: make(map[string]*User),
	}
}

func (a *MemoryAuthProvide) AuthenticateUser(username, password string) bool {
	if user, ok := a.users[username]; ok {
		return VerifyPassword(user.Hash, password)
	}
	return false
}

func (a *MemoryAuthProvide) AuthenticateWithAppPassword(username, password string) bool {
	if user, ok := a.users[username]; ok {
		for _, appPassword := range user.AppPasswords {
			if VerifyPassword(appPassword.Hash, password) && !appPassword.Revoked {
				if appPassword.ExpiresAt.IsZero() || time.Now().Before(appPassword.ExpiresAt) {
					return true
				}
			}
		}
	}
	return false
}

func (a *MemoryAuthProvide) AddUser(username, hash, role string) error {

	if _, ok := a.users[username]; ok {
		return fmt.Errorf("user already exists")
	}

	a.users[username] = &User{
		Username:     username,
		Hash:         hash,
		Role:         role,
		AppPasswords: []AppPassword{},
	}

	return nil
}

func (a *MemoryAuthProvide) RemoveUser(username string) error {

	if _, ok := a.users[username]; !ok {
		return fmt.Errorf("user does not exist")
	}

	delete(a.users, username)
	return nil
}

func (a *MemoryAuthProvide) GetUsers() ([]string, error) {
	users := make([]string, 0, len(a.users))
	for user := range a.users {
		users = append(users, user)
	}
	return users, nil
}

func (a *MemoryAuthProvide) ChangePassword(username, hash string) error {
	if _, ok := a.users[username]; !ok {
		return fmt.Errorf("user does not exist")
	}
	a.users[username].Hash = hash
	return nil
}

func (a *MemoryAuthProvide) DropUsers() error {
	a.users = make(map[string]*User)
	return nil
}

func (a *MemoryAuthProvide) LoadUsers() error {
	return fmt.Errorf("not implemented")
}

func (a *MemoryAuthProvide) GetRole(username string) (string, error) {
	if user, ok := a.users[username]; ok {
		return user.Role, nil
	}
	return "", fmt.Errorf("user does not exist")
}

func (a *MemoryAuthProvide) GetUser(username string) (UserView, error) {
	if user, ok := a.users[username]; ok {
		return UserView{
			Username: user.Username,
			Role:     user.Role,
		}, nil
	}
	return UserView{}, fmt.Errorf("user does not exist")
}

func (a *MemoryAuthProvide) SetRole(username, role string) error {
	if user, ok := a.users[username]; ok {
		user.Role = role
		return nil
	}
	return fmt.Errorf("user does not exist")
}

func (a *MemoryAuthProvide) AddAppPassword(username, hash string, expire int) error {
	if user, ok := a.users[username]; ok {
		appPassword := AppPassword{
			ID:        GenerateUniqueID(), // Implement a function to generate unique IDs
			Hash:      hash,
			ExpiresAt: time.Now().Add(time.Duration(expire) * time.Hour),
			CreatedAt: time.Now(),
			Revoked:   false,
		}
		user.AppPasswords = append(user.AppPasswords, appPassword)
		return nil
	}
	return fmt.Errorf("user does not exist")
}

func (a *MemoryAuthProvide) RevokeAppPassword(username, id string) error {
	if user, ok := a.users[username]; ok {
		for i, appPassword := range user.AppPasswords {
			if appPassword.ID == id {
				user.AppPasswords[i].Revoked = true
				return nil
			}
		}
	}
	return fmt.Errorf("user or app password does not exist")
}

func (a *MemoryAuthProvide) ListAppPasswordsIds(username string) ([]string, error) {
	if user, ok := a.users[username]; ok {
		ids := make([]string, 0, len(user.AppPasswords))
		for _, appPassword := range user.AppPasswords {
			ids = append(ids, appPassword.ID)
		}
		return ids, nil
	}
	return nil, fmt.Errorf("user does not exist")
}

func (a *MemoryAuthProvide) CleanUpRevokedExpiredAppPasswords() error {
	for _, user := range a.users {
		for i := len(user.AppPasswords) - 1; i >= 0; i-- {
			appPassword := user.AppPasswords[i]
			if appPassword.Revoked || (!appPassword.ExpiresAt.IsZero() && time.Now().After(appPassword.ExpiresAt)) {
				user.AppPasswords = append(user.AppPasswords[:i], user.AppPasswords[i+1:]...)
			}
		}
	}
	return nil
}
