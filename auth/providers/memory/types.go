package providers

import (
	"encoding/json"

	providerTypes "github.com/a13labs/a13core/auth/providers/types"
)

type MemoryAuthProvider struct {
	providerTypes.AuthProvider
	users map[string]*providerTypes.User
}

func FromConfig(config json.RawMessage) providerTypes.AuthProvider {
	return &MemoryAuthProvider{
		users: make(map[string]*providerTypes.User),
	}
}
