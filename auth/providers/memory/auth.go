package providers

import (
	"time"

	"github.com/a13labs/a13core/auth/providers/internal"
	providerTypes "github.com/a13labs/a13core/auth/providers/types"
)

func (a *MemoryAuthProvider) Authenticate(username, password string) *providerTypes.UserView {
	if user, ok := a.users[username]; ok {
		if internal.VerifyPassword(user.Hash, password) {
			return &providerTypes.UserView{
				Username: user.Username,
				Role:     user.Role,
			}
		}

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
