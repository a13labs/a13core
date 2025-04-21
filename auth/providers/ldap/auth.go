package ldap

import (
	"fmt"

	"gopkg.in/ldap.v2"

	providerTypes "github.com/a13labs/a13core/auth/providers/types"
)

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
