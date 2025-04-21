package providers

import (
	"fmt"
	"time"

	"github.com/a13labs/a13core/auth/providers/internal"
	providerTypes "github.com/a13labs/a13core/auth/providers/types"
)

func (a *MemoryAuthProvider) AddUser(username, password, role string) error {

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

func (a *MemoryAuthProvider) RemoveUser(username string) error {

	if _, ok := a.users[username]; !ok {
		return fmt.Errorf("user does not exist")
	}

	delete(a.users, username)
	return nil
}

func (a *MemoryAuthProvider) GetUsers() ([]providerTypes.UserView, error) {
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

func (a *MemoryAuthProvider) ChangePassword(username, password string) error {
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

func (a *MemoryAuthProvider) DropUsers() error {
	a.users = make(map[string]*providerTypes.User)
	return nil
}

func (a *MemoryAuthProvider) LoadUsers() error {
	return nil
}

func (a *MemoryAuthProvider) GetRole(username string) (string, error) {
	if user, ok := a.users[username]; ok {
		return user.Role, nil
	}
	return "", fmt.Errorf("user does not exist")
}

func (a *MemoryAuthProvider) GetUser(username string) (providerTypes.UserView, error) {
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

func (a *MemoryAuthProvider) SetRole(username, role string) error {
	if user, ok := a.users[username]; ok {
		user.Role = role
		return nil
	}
	return fmt.Errorf("user does not exist")
}

func (a *MemoryAuthProvider) AddAppPassword(username, password, role string, expire int) (string, error) {
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

func (a *MemoryAuthProvider) RevokeAppPassword(username, id string) error {
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

func (a *MemoryAuthProvider) GetAppPasswords(username string) ([]providerTypes.AppPasswordView, error) {
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

func (a *MemoryAuthProvider) CleanUpRevokedExpiredAppPasswords() error {
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
