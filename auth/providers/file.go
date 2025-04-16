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

func (a *FileAuthProvider) AuthenticateUser(username, password string) bool {
	err := a.LoadUsers()
	if err != nil {
		return false
	}

	for _, user := range a.users.Users {
		if user.Username == username && VerifyPassword(user.Password, password) {
			return true
		}
	}
	return false
}

func (a *FileAuthProvider) AuthenticateWithAppPassword(username, password string) bool {
	err := a.LoadUsers()
	if err != nil {
		return false
	}
	for _, user := range a.users.Users {
		if user.Username == username {
			for _, appPassword := range user.AppPasswords {
				if VerifyPassword(appPassword.Hash, password) && !appPassword.Revoked {
					if appPassword.ExpiresAt.IsZero() || time.Now().Before(appPassword.ExpiresAt) {
						return true
					}
				}
			}
		}
	}
	return false
}

func (a *FileAuthProvider) AddUser(username, password, role string) error {
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
	hashedPassword, err := HashPassword(password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}
	a.users.Users = append(a.users.Users, User{
		Username:     username,
		Password:     hashedPassword,
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

func (a *FileAuthProvider) ChangePassword(username, password string) error {
	err := a.LoadUsers()
	if err != nil {
		return err
	}
	a.userStoreMux.Lock()
	defer a.userStoreMux.Unlock()
	for i, user := range a.users.Users {
		if user.Username == username {
			hashedPassword, err := HashPassword(password)
			if err != nil {
				return fmt.Errorf("failed to hash password: %v", err)
			}
			a.users.Users[i].Password = hashedPassword
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
			return UserView{
				Username: a.users.Users[i].Username,
				Role:     a.users.Users[i].Role,
			}, nil
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

func (a *FileAuthProvider) AddAppPassword(username, password string, expire int) error {
	err := a.LoadUsers()
	if err != nil {
		return err
	}
	a.userStoreMux.Lock()
	defer a.userStoreMux.Unlock()
	for i, user := range a.users.Users {
		if user.Username == username {
			hashedPassword, err := HashPassword(password)
			if err != nil {
				return fmt.Errorf("failed to hash password: %v", err)
			}
			appPassword := AppPassword{
				ID:        GenerateUniqueID(), // Implement a function to generate unique IDs
				Hash:      hashedPassword,
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(time.Duration(expire) * time.Hour),
				Revoked:   false,
			}
			a.users.Users[i].AppPasswords = append(a.users.Users[i].AppPasswords, appPassword)
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
	return fmt.Errorf("user not found")
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

func (a *FileAuthProvider) ListAppPasswordsIds(username string) ([]string, error) {
	err := a.LoadUsers()
	if err != nil {
		return nil, err
	}
	a.userStoreMux.Lock()
	defer a.userStoreMux.Unlock()
	for i, user := range a.users.Users {
		if user.Username == username {
			var ids []string
			for _, appPassword := range a.users.Users[i].AppPasswords {
				ids = append(ids, appPassword.ID)
			}
			return ids, nil
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
