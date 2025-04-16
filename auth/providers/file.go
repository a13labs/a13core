package providers

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type FileAuthProviderConfig struct {
	FilePath string `json:"file_path"`
}

type FileAuthProvider struct {
	AuthProvider
	userStoreMux sync.Mutex
	users        Users
	config       FileAuthProviderConfig
}

func NewFileAuthProvider(config json.RawMessage) AuthProvider {

	var c FileAuthProviderConfig
	if err := json.Unmarshal([]byte(config), &c); err != nil {
		return nil
	}
	return &FileAuthProvider{config: c}
}

func (a *FileAuthProvider) AuthenticateUser(username, password string) *UserView {
	err := a.LoadUsers()
	if err != nil {
		return nil
	}

	for _, user := range a.users.Users {
		if user.Username == username && VerifyPassword(user.Hash, password) {
			return &UserView{
				Username: user.Username,
				Role:     user.Role,
			}
		}
	}
	return nil
}

func (a *FileAuthProvider) AuthenticateWithAppPassword(username, password string) *UserView {
	err := a.LoadUsers()
	if err != nil {
		return nil
	}
	for _, user := range a.users.Users {
		if user.Username == username {
			for _, appPassword := range user.AppPasswords {
				if VerifyPassword(appPassword.Hash, password) && !appPassword.Revoked {
					if appPassword.ExpiresAt.IsZero() || time.Now().Before(appPassword.ExpiresAt) {
						return &UserView{
							Username: user.Username,
							Role:     user.Role,
							AppPasswords: []AppPasswordView{
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
	}
	return nil
}

func (a *FileAuthProvider) AddUser(username, hash, role string) error {
	err := a.LoadUsers()
	if err != nil {
		return err
	}
	// check if user already exists
	a.userStoreMux.Lock()
	defer a.userStoreMux.Unlock()
	for _, user := range a.users.Users {
		if user.Username == username {
			return fmt.Errorf("user already exists")
		}
	}
	a.users.Users = append(a.users.Users, User{
		Username:     username,
		Hash:         hash,
		Role:         role,
		AppPasswords: []AppPassword{},
	})
	data, err := json.MarshalIndent(a.users, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.Create(a.config.FilePath)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(data)
	return err
}

func (a *FileAuthProvider) RemoveUser(username string) error {
	err := a.LoadUsers()
	if err != nil {
		return err
	}
	a.userStoreMux.Lock()
	defer a.userStoreMux.Unlock()
	for i, user := range a.users.Users {
		if user.Username == username {
			a.users.Users = append(a.users.Users[:i], a.users.Users[i+1:]...)
			data, err := json.MarshalIndent(a.users, "", "  ")
			if err != nil {
				return err
			}
			file, err := os.Create(a.config.FilePath)
			if err != nil {
				return err
			}
			defer file.Close()
			_, err = file.Write(data)
			return err
		}
	}
	return fmt.Errorf("user not found")
}

func (a *FileAuthProvider) GetUsers() ([]string, error) {
	err := a.LoadUsers()
	if err != nil {
		return nil, err
	}
	var usernames []string
	for _, user := range a.users.Users {
		usernames = append(usernames, user.Username)
	}
	return usernames, nil
}

func (a *FileAuthProvider) ChangePassword(username, hash string) error {
	err := a.LoadUsers()
	if err != nil {
		return err
	}
	a.userStoreMux.Lock()
	defer a.userStoreMux.Unlock()
	for i, user := range a.users.Users {
		if user.Username == username {
			a.users.Users[i].Hash = hash
			data, err := json.MarshalIndent(a.users, "", "  ")
			if err != nil {
				return err
			}
			file, err := os.Create(a.config.FilePath)
			if err != nil {
				return err
			}
			defer file.Close()
			_, err = file.Write(data)
			return err
		}
	}
	return fmt.Errorf("user not found")
}

func (a *FileAuthProvider) DropUsers() error {
	a.userStoreMux.Lock()
	defer a.userStoreMux.Unlock()
	file, err := os.Create(a.config.FilePath)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write([]byte("{\"users\":[]}"))
	return err
}

func (a *FileAuthProvider) LoadUsers() error {
	a.userStoreMux.Lock()
	defer a.userStoreMux.Unlock()

	if _, err := os.Stat(a.config.FilePath); os.IsNotExist(err) {
		file, err := os.Create(a.config.FilePath)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = file.Write([]byte("{\"users\":[]}"))
		if err != nil {
			return err
		}
	}

	file, err := os.Open(a.config.FilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	body, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	content := string(body)

	if err := json.Unmarshal([]byte(content), &a.users); err != nil {
		return err
	}
	return nil
}

func (a *FileAuthProvider) GetRole(username string) (string, error) {
	err := a.LoadUsers()
	if err != nil {
		return "", err
	}
	a.userStoreMux.Lock()
	defer a.userStoreMux.Unlock()
	for i, user := range a.users.Users {
		if user.Username == username {
			return a.users.Users[i].Role, nil
		}
	}

	return "", fmt.Errorf("user not found")
}

func (a *FileAuthProvider) GetUser(username string) (UserView, error) {
	err := a.LoadUsers()
	if err != nil {
		return UserView{}, err
	}
	a.userStoreMux.Lock()
	defer a.userStoreMux.Unlock()
	for i, user := range a.users.Users {
		if user.Username == username {
			userView := UserView{
				Username:     a.users.Users[i].Username,
				Role:         a.users.Users[i].Role,
				AppPasswords: []AppPasswordView{},
			}
			for _, appPassword := range a.users.Users[i].AppPasswords {
				userView.AppPasswords = append(userView.AppPasswords, AppPasswordView{
					ID:        appPassword.ID,
					CreatedAt: appPassword.CreatedAt,
					ExpiresAt: appPassword.ExpiresAt,
					Role:      appPassword.Role,
					Revoked:   appPassword.Revoked,
				})
			}
			return userView, nil
		}
	}
	return UserView{}, fmt.Errorf("user not found")
}

func (a *FileAuthProvider) SetRole(username, role string) error {
	err := a.LoadUsers()
	if err != nil {
		return err
	}
	a.userStoreMux.Lock()
	defer a.userStoreMux.Unlock()
	for i, user := range a.users.Users {
		if user.Username == username {
			a.users.Users[i].Role = role
			data, err := json.MarshalIndent(a.users, "", "  ")
			if err != nil {
				return err
			}
			file, err := os.Create(a.config.FilePath)
			if err != nil {
				return err
			}
			defer file.Close()
			_, err = file.Write(data)
			return err
		}
	}
	return fmt.Errorf("user not found")
}

func (a *FileAuthProvider) AddAppPassword(username, hash, role string, expire int) (string, error) {
	err := a.LoadUsers()
	if err != nil {
		return "", err
	}
	a.userStoreMux.Lock()
	defer a.userStoreMux.Unlock()
	for i, user := range a.users.Users {
		if user.Username == username {
			appPassword := AppPassword{
				ID:        GenerateUniqueID(), // Implement a function to generate unique IDs
				Hash:      hash,
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(time.Duration(expire) * time.Hour),
				Role:      role,
				Revoked:   false,
			}
			a.users.Users[i].AppPasswords = append(a.users.Users[i].AppPasswords, appPassword)
			data, err := json.MarshalIndent(a.users, "", "  ")
			if err != nil {
				return "", err
			}
			file, err := os.Create(a.config.FilePath)
			if err != nil {
				return "", err
			}
			defer file.Close()
			_, err = file.Write(data)
			return appPassword.ID, nil
		}
	}
	return "", fmt.Errorf("user not found")
}

func (a *FileAuthProvider) RevokeAppPassword(username, id string) error {
	err := a.LoadUsers()
	if err != nil {
		return err
	}
	a.userStoreMux.Lock()
	defer a.userStoreMux.Unlock()
	for i, user := range a.users.Users {
		if user.Username == username {
			for j, appPassword := range a.users.Users[i].AppPasswords {
				if appPassword.ID == id {
					a.users.Users[i].AppPasswords[j].Revoked = true
					data, err := json.MarshalIndent(a.users, "", "  ")
					if err != nil {
						return err
					}
					file, err := os.Create(a.config.FilePath)
					if err != nil {
						return err
					}
					defer file.Close()
					_, err = file.Write(data)
					return nil
				}
			}
		}
	}
	return fmt.Errorf("user or app password not found")
}

func (a *FileAuthProvider) GetAppPasswords(username string) ([]AppPasswordView, error) {
	err := a.LoadUsers()
	if err != nil {
		return nil, err
	}
	a.userStoreMux.Lock()
	defer a.userStoreMux.Unlock()
	for i, user := range a.users.Users {
		if user.Username == username {
			appPasswords := make([]AppPasswordView, 0, len(user.AppPasswords))
			for _, appPassword := range a.users.Users[i].AppPasswords {
				appPasswords = append(appPasswords, AppPasswordView{
					ID:        appPassword.ID,
					CreatedAt: appPassword.CreatedAt,
					ExpiresAt: appPassword.ExpiresAt,
					Role:      appPassword.Role,
					Revoked:   appPassword.Revoked,
				})
			}
			return appPasswords, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

func (a *FileAuthProvider) CleanUpRevokedExpiredAppPasswords() error {
	err := a.LoadUsers()
	if err != nil {
		return err
	}
	a.userStoreMux.Lock()
	defer a.userStoreMux.Unlock()
	for i, _ := range a.users.Users {
		var validAppPasswords []AppPassword
		for _, appPassword := range a.users.Users[i].AppPasswords {
			if !appPassword.Revoked && (appPassword.ExpiresAt.IsZero() || time.Now().Before(appPassword.ExpiresAt)) {
				validAppPasswords = append(validAppPasswords, appPassword)
			}
		}
		a.users.Users[i].AppPasswords = validAppPasswords
	}
	data, err := json.MarshalIndent(a.users, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.Create(a.config.FilePath)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(data)
	return err
}
