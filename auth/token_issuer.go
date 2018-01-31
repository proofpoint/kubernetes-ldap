package auth

import (
	"net/http"

	goldap "github.com/go-ldap/ldap"
	"github.com/golang/glog"
	"github.com/proofpoint/kubernetes-ldap/ldap"
	"github.com/proofpoint/kubernetes-ldap/token"
	"strings"
	"time"
)

// LDAPTokenIssuer issues cryptographically secure tokens after authenticating the
// user against a backing LDAP directory.
type LDAPTokenIssuer struct {
	LDAPServer        string
	LDAPAuthenticator ldap.Authenticator
	TokenSigner       token.Signer
	TTL               time.Duration
	UsernameAttribute string
}

func (lti *LDAPTokenIssuer) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	user, password, ok := req.BasicAuth()
	if !ok {
		resp.Header().Add("WWW-Authenticate", `Basic realm="kubernetes ldap"`)
		resp.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Authenticate the user via LDAP
	ldapEntry, err := lti.LDAPAuthenticator.Authenticate(user, password)
	if err != nil {
		glog.Errorf("Error authenticating user: %v", err)
		resp.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Auth was successful, create token
	token := lti.createToken(ldapEntry)

	// Sign token and return
	signedToken, err := lti.TokenSigner.Sign(token)
	if err != nil {
		glog.Errorf("Error signing token: %v", err)
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp.Header().Add("Content-Type", "text/plain")
	resp.Write([]byte(signedToken))
}

func (lti *LDAPTokenIssuer) getGroupsFromMembersOf(membersOf []string) []string {
	groupsOf := []string{}
	uniqueGroups := make(map[string]struct{})

	for _, memberOf := range membersOf {
		splittedStr := strings.Split(memberOf, ",")
		for _, element := range splittedStr {
			element = strings.ToLower(element)
			if !strings.Contains(element, "cn=") {
				continue
			}

			group := strings.Replace(element, "cn=", "", -1)

			if _, ok := uniqueGroups[group]; ok {
				//this group has been considered and added already
				continue
			}

			groupsOf = append(groupsOf, group)
			uniqueGroups[group] = struct{}{}
		}
	}

	return groupsOf
}

func (lti *LDAPTokenIssuer) createToken(ldapEntry *goldap.Entry) *token.AuthToken {
	username := ldapEntry.DN
	if lti.UsernameAttribute != "" {
		username = ldapEntry.GetAttributeValue(lti.UsernameAttribute)
	}

	return &token.AuthToken{
		Username: username,
		Groups:   lti.getGroupsFromMembersOf(ldapEntry.GetAttributeValues("memberOf")),
		Assertions: map[string]string{
			"ldapServer": lti.LDAPServer,
			"userDN":     ldapEntry.DN,
		},
		Expiration: lti.getExpirationTime(),
	}
}

func (lti *LDAPTokenIssuer) getExpirationTime() int64 {
	nowMillis := time.Now().UnixNano() / int64(time.Millisecond)
	ttlMillis := int64(time.Duration(lti.TTL) / time.Millisecond)

	return nowMillis + ttlMillis
}
