package ldap

import (
	"crypto/tls"

	"encoding/json"
	"fmt"

	"gopkg.in/ldap.v2"

	providerTypes "github.com/a13labs/a13core/auth/providers/types"
)

type LDAPAuthConfig struct {
	Attributes         []string          `json:"attributes,omitempty"`
	BaseDN             string            `json:"base_dn"`
	BindDN             string            `json:"bind_dn"`
	BindPassword       string            `json:"bind_password"`
	GroupFilter        string            `json:"group_filter,omitempty"` // e.g. "(member=%s)"
	Host               string            `json:"host"`
	ServerName         string            `json:"server_name,omitempty"`
	UserFilter         string            `json:"user_filter,omitempty"` // e.g. "(uid=%s)"
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

func ValidateConfig(config json.RawMessage) error {
	var c LDAPAuthConfig
	if err := json.Unmarshal([]byte(config), &c); err != nil {
		return err
	}

	if c.Host == "" {
		return fmt.Errorf("host is required")
	}
	if c.BaseDN == "" {
		return fmt.Errorf("base is required")
	}
	if c.BindDN == "" {
		return fmt.Errorf("bind_dn is required")
	}
	if c.BindPassword == "" {
		return fmt.Errorf("bind_password is required")
	}

	return nil
}

func FromConfig(config json.RawMessage) providerTypes.AuthProvider {

	err := ValidateConfig(config)
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

// Connect connects to the ldap backend.
func (a *LDAPAuth) dial() (*ldap.Conn, error) {
	var l *ldap.Conn
	var err error
	address := fmt.Sprintf("%s:%d", a.config.Host, a.config.Port)
	if !a.config.UseSSL {
		l, err = ldap.Dial("tcp", address)
		if err != nil {
			return nil, err
		}

		// Reconnect with TLS
		if !a.config.SkipTLS {
			err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
			if err != nil {
				return nil, err
			}
		}
	} else {
		config := &tls.Config{
			InsecureSkipVerify: a.config.InsecureSkipVerify,
			ServerName:         a.config.ServerName,
		}
		if a.config.ClientCertificates != nil && len(a.config.ClientCertificates) > 0 {
			config.Certificates = a.config.ClientCertificates
		}
		l, err = ldap.DialTLS("tcp", address, config)
		if err != nil {
			return nil, err
		}
	}

	return l, nil
}

func (a *LDAPAuth) Authenticate(username, password string) *providerTypes.UserView {
	c, err := a.dial()
	if err != nil {
		return nil
	}
	defer c.Close()

	// First bind with a read only user
	err = c.Bind(a.config.BindDN, a.config.BindPassword)
	if err != nil {
		return nil
	}

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		a.config.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(a.config.UserFilter, username),
		a.config.Attributes,
		nil,
	)

	sr, err := c.Search(searchRequest)
	if err != nil {
		return nil
	}

	if len(sr.Entries) != 1 {
		return nil
	}

	userDN := sr.Entries[0].DN
	gidNumber := sr.Entries[0].GetAttributeValue("gidNumber")

	searchRequest = ldap.NewSearchRequest(
		fmt.Sprintf("ou=groups,%s", a.config.BaseDN),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(a.config.GroupFilter, gidNumber),
		a.config.Attributes,
		nil,
	)

	err = c.Bind(a.config.BindDN, a.config.BindPassword)
	if err != nil {
		return nil
	}

	sr, err = c.Search(searchRequest)
	if err != nil {
		return nil
	}

	if len(sr.Entries) != 1 {
		return nil
	}

	role := sr.Entries[0].GetAttributeValue("ou")

	// Now bind with the user DN to authenticate
	err = c.Bind(userDN, password)
	if err != nil {
		return nil
	}

	return &providerTypes.UserView{
		Username:     username,
		Role:         role,
		AppPasswords: make([]providerTypes.AppPasswordView, 0),
	}
}

func (a *LDAPAuth) AuthenticateUser(username, password string) *providerTypes.UserView {
	return a.Authenticate(username, password)
}

func (a *LDAPAuth) AuthenticateWithAppPassword(username, password string) *providerTypes.UserView {
	return a.Authenticate(username, password)
}
