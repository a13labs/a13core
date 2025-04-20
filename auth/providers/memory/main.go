package providers

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/a13labs/a13core/auth/providers/internal"
	providerTypes "github.com/a13labs/a13core/auth/providers/types"
)

type MemoryAuthProvide struct {
	providerTypes.AuthProvider
	users map[string]*providerTypes.User
}

func FromConfig(config json.RawMessage) providerTypes.AuthProvider {
	return &MemoryAuthProvide{
		users: make(map[string]*providerTypes.User),
	}
}

func (a *MemoryAuthProvide) AuthenticateUser(username, password string) *providerTypes.UserView {
	if user, ok := a.users[username]; ok {
		if internal.VerifyPassword(user.Hash, password) {
			return &providerTypes.UserView{
				Username: user.Username,
				Role:     user.Role,
			}
		}
	}
	return nil
}

func (a *MemoryAuthProvide) AuthenticateWithAppPassword(username, password string) *providerTypes.UserView {
	if user, ok := a.users[username]; ok {
		for _, appPassword := range user.AppPasswords {
			if internal.VerifyPassword(appPassword.Hash, password) && !appPassword.Revoked {
				if appPassword.ExpiresAt.IsZero() || time.Now().Before(appPassword.ExpiresAt) {
					return &providerTypes.UserView{
						Username: user.Username,
						Role:     user.Role,
						AppPasswords: []providerTypes.AppPasswordView{
							{
								ID:        appPassword.ID,
								CreatedAt: appPassword.CreatedAt,
								ExpiresAt: appPassword.ExpiresAt,
								Role:      appPassword.Role,
								Revoked:   appPassword.Revoked,
							},
						},
					}
				}
			}
		}
	}
	return nil
}

func (a *MemoryAuthProvide) AddUser(username, password, role string) error {

	if _, ok := a.users[username]; ok {
		return fmt.Errorf("user already exists")
	}

	hash, err := internal.HashPassword(password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	a.users[username] = &providerTypes.User{
		Username:     username,
		Hash:         hash,
		Role:         role,
		AppPasswords: []providerTypes.AppPassword{},
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

func (a *MemoryAuthProvide) GetUsers() ([]providerTypes.UserView, error) {
	users := make([]providerTypes.UserView, 0, len(a.users))
	i := 0
	for user := range a.users {
		users = append(users, providerTypes.UserView{
			Username:     user,
			Role:         a.users[user].Role,
			AppPasswords: make([]providerTypes.AppPasswordView, 0, len(a.users[user].AppPasswords)),
		})
		for _, appPassword := range a.users[user].AppPasswords {
			users[i].AppPasswords = append(users[i].AppPasswords, providerTypes.AppPasswordView{
				ID:        appPassword.ID,
				CreatedAt: appPassword.CreatedAt,
				ExpiresAt: appPassword.ExpiresAt,
				Role:      appPassword.Role,
				Revoked:   appPassword.Revoked,
			})
		}
		i++
	}
	return users, nil
}

func (a *MemoryAuthProvide) ChangePassword(username, password string) error {
	if _, ok := a.users[username]; !ok {
		return fmt.Errorf("user does not exist")
	}
	hash, err := internal.HashPassword(password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}
	a.users[username].Hash = hash
	return nil
}

func (a *MemoryAuthProvide) DropUsers() error {
	a.users = make(map[string]*providerTypes.User)
	return nil
}

func (a *MemoryAuthProvide) LoadUsers() error {
	return nil
}

func (a *MemoryAuthProvide) GetRole(username string) (string, error) {
	if user, ok := a.users[username]; ok {
		return user.Role, nil
	}
	return "", fmt.Errorf("user does not exist")
}

func (a *MemoryAuthProvide) GetUser(username string) (providerTypes.UserView, error) {
	if user, ok := a.users[username]; ok {
		userView := providerTypes.UserView{
			Username:     user.Username,
			Role:         user.Role,
			AppPasswords: make([]providerTypes.AppPasswordView, 0, len(user.AppPasswords)),
		}
		for _, appPassword := range user.AppPasswords {
			userView.AppPasswords = append(userView.AppPasswords, providerTypes.AppPasswordView{
				ID:        appPassword.ID,
				CreatedAt: appPassword.CreatedAt,
				ExpiresAt: appPassword.ExpiresAt,
				Role:      appPassword.Role,
				Revoked:   appPassword.Revoked,
			})
		}
		return userView, nil
	}
	return providerTypes.UserView{}, fmt.Errorf("user does not exist")
}

func (a *MemoryAuthProvide) SetRole(username, role string) error {
	if user, ok := a.users[username]; ok {
		user.Role = role
		return nil
	}
	return fmt.Errorf("user does not exist")
}

func (a *MemoryAuthProvide) AddAppPassword(username, password, role string, expire int) (string, error) {
	if user, ok := a.users[username]; ok {

		hash, err := internal.HashPassword(password)
		if err != nil {
			return "", fmt.Errorf("failed to hash password: %v", err)
		}

		appPassword := providerTypes.AppPassword{
			ID:        internal.GenerateUniqueID(), // Implement a function to generate unique IDs
			Hash:      hash,
			ExpiresAt: time.Now().Add(time.Duration(expire) * time.Hour),
			CreatedAt: time.Now(),
			Role:      role,
			Revoked:   false,
		}
		user.AppPasswords = append(user.AppPasswords, appPassword)
		return appPassword.ID, nil
	}
	return "", fmt.Errorf("user does not exist")
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

func (a *MemoryAuthProvide) GetAppPasswords(username string) ([]providerTypes.AppPasswordView, error) {
	if user, ok := a.users[username]; ok {
		appPasswords := make([]providerTypes.AppPasswordView, 0, len(user.AppPasswords))
		for _, appPassword := range user.AppPasswords {
			appPasswords = append(appPasswords, providerTypes.AppPasswordView{
				ID:        appPassword.ID,
				CreatedAt: appPassword.CreatedAt,
				ExpiresAt: appPassword.ExpiresAt,
				Role:      appPassword.Role,
				Revoked:   appPassword.Revoked,
			})
		}
		return appPasswords, nil
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
