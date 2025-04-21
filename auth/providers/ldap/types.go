package ldap

import (
	"crypto/tls"

	"encoding/json"

	providerTypes "github.com/a13labs/a13core/auth/providers/types"
)

type LDAPAuthConfig struct {
	Attributes         []string          `json:"attributes,omitempty"`
	BaseDN             string            `json:"base_dn"`
	BindDN             string            `json:"bind_dn"`
	BindPassword       string            `json:"bind_password"`
	GroupFilter        string            `json:"group_filter,omitempty"`
	Host               string            `json:"host"`
	UserFilter         string            `json:"user_filter,omitempty"`
	Port               int               `json:"port,omitempty"`
	InsecureSkipVerify bool              `json:"insecure,omitempty"`
	UseSSL             bool              `json:"use_ssl,omitempty"`
	SkipTLS            bool              `json:"skip_tls,omitempty"`
	ClientCertificates []tls.Certificate `json:"client_certificates,omitempty"`
}

type LDAPAuth struct {
	providerTypes.AuthProvider
	config LDAPAuthConfig
}

func FromConfig(config json.RawMessage) providerTypes.AuthProvider {

	err := validateConfig(config)
	if err != nil {
		return nil
	}

	var c LDAPAuthConfig
	if err := json.Unmarshal([]byte(config), &c); err != nil {
		return nil
	}

	if c.Port == 0 {
		c.Port = 389
		if c.UseSSL {
			c.Port = 636
		}
	}
	if c.Attributes == nil {
		c.Attributes = []string{"name", "cn", "mail", "uidnumber", "gidnumber", "ou"}
	}

	if c.UserFilter == "" {
		c.UserFilter = "(cn=%s)"
	}
	if c.GroupFilter == "" {
		c.GroupFilter = "(gidNumber=%s)"
	}

	return &LDAPAuth{
		config: c,
	}
}
