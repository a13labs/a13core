package ldap

import (
	"crypto/tls"

	"encoding/json"
	"fmt"

	"gopkg.in/ldap.v2"
)

func validateConfig(config json.RawMessage) error {
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
