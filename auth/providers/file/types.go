package file

import (
	"encoding/json"
	"sync"

	providerTypes "github.com/a13labs/a13core/auth/providers/types"
)

type FileAuthProviderConfig struct {
	FilePath string `json:"file_path"`
}

type FileAuthProvider struct {
	providerTypes.AuthProvider
	userStoreMux sync.Mutex
	users        providerTypes.Users
	config       FileAuthProviderConfig
}

func FromConfig(config json.RawMessage) providerTypes.AuthProvider {

	var c FileAuthProviderConfig
	if err := json.Unmarshal([]byte(config), &c); err != nil {
		return nil
	}
	return &FileAuthProvider{config: c}
}
