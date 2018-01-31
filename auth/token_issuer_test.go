package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-ldap/ldap"
	"github.com/proofpoint/kubernetes-ldap/token"
	"time"
)

type dummyLDAP struct {
	entry *ldap.Entry
	err   error
}

func (d dummyLDAP) Authenticate(username, password string) (*ldap.Entry, error) {
	return d.entry, d.err
}

type dummySigner struct {
	signed string
	err    error
}

func (d dummySigner) Sign(token *token.AuthToken) (string, error) {
	return d.signed, d.err
}

func TestTokenIssuer(t *testing.T) {
	cases := []struct {
		basicAuth    bool
		ldapEntry    *ldap.Entry
		expectedCode int
		ldapErr      error
		signerErr    error
	}{
		{
			// Happy path, user was authenticated against LDAP server
			basicAuth:    true,
			ldapEntry:    &ldap.Entry{},
			expectedCode: http.StatusOK,
		},
		{
			// Invalid LDAP creds provided by user
			basicAuth:    true,
			ldapErr:      errors.New("Invalid username/password"),
			expectedCode: http.StatusUnauthorized,
		},
		{
			// User did not provide credentials via Basic Auth
			basicAuth:    false,
			expectedCode: http.StatusUnauthorized,
		},
		{
			// Signing token failed
			basicAuth:    true,
			expectedCode: http.StatusInternalServerError,
			ldapEntry:    &ldap.Entry{},
			signerErr:    errors.New("Something failed while signing token"),
		},
	}

	for i, c := range cases {
		lti := LDAPTokenIssuer{
			LDAPAuthenticator: dummyLDAP{c.ldapEntry, c.ldapErr},
			TokenSigner:       dummySigner{"signedToken", c.signerErr},
			UsernameAttribute: "mail",
		}

		req, err := http.NewRequest("GET", "", nil)
		if err != nil {
			t.Errorf("Case: %d. Failed to create request: %v", i, err)
		}
		if c.basicAuth {
			req.SetBasicAuth("user", "password")
		}

		rec := httptest.NewRecorder()
		lti.ServeHTTP(rec, req)

		if rec.Code != c.expectedCode {
			t.Errorf("Case: %d. Expected %d, got %d", i, c.expectedCode, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "signedToken") && c.expectedCode == http.StatusOK {
			t.Errorf("Case: %d. body did not contain expected token. body contents: %q", i, rec.Body.String())
		}
	}
}

func TestCreateToken(t *testing.T) {
	e := &ldap.Entry{
		DN: "some-dn",
		Attributes: []*ldap.EntryAttribute{
			{
				Name:   "uid",
				Values: []string{"username"},
			},
			{
				Name:   "mail",
				Values: []string{"username@example.com"},
			},
			{
				Name: "memberOf",
				Values: []string{
					"cn=sg-grp1,ou=ORG,ou=Groups,dc=lab,dc=example,dc=com",
					"CN=sg-grp2,ou=ORG,ou=Groups,dc=lab,dc=example,dc=com",
					"CN=sg-grp1,ou=ORG2,ou=Groups,dc=lab,dc=example,dc=com",
				},
			},
		},
	}

	cases := []struct {
		name               string
		tokenIssuer        LDAPTokenIssuer
		expectedAssertions map[string]string
		expectedUsername   string
		expectedGroups     []string
	}{
		{
			name: "get mail as username attribute",
			tokenIssuer: LDAPTokenIssuer{
				LDAPServer:        "some-ldap-server",
				UsernameAttribute: "mail",
			},
			expectedAssertions: map[string]string{
				"ldapServer": "some-ldap-server",
				"userDN":     e.DN,
			},
			expectedUsername: "username@example.com",
			expectedGroups: []string{
				"sg-grp1",
				"sg-grp2",
			},
		},
		{
			name: "verify backward compatibility",
			tokenIssuer: LDAPTokenIssuer{
				LDAPServer: "some-ldap-server",
			},
			expectedAssertions: map[string]string{
				"ldapServer": "some-ldap-server",
				"userDN":     e.DN,
			},
			expectedUsername: e.DN,
			expectedGroups: []string{
				"sg-grp1",
				"sg-grp2",
			},
		},
	}

	for _, testcase := range cases {
		tok := testcase.tokenIssuer.createToken(e)
		if tok.Username != testcase.expectedUsername {
			t.Errorf("Unexpected username in token. Expected: '%s'. Got: '%s'.", testcase.expectedUsername, tok.Username)
		}

		for k, v := range testcase.expectedAssertions {
			if tok.Assertions[k] != v {
				t.Errorf("Expected assertion '%s' to be '%s'. Got '%s'", k, v, tok.Assertions[k])
			}
		}
	}
}

func TestTTL(t *testing.T) {
	e := &ldap.Entry{
		DN: "some-dn",
	}

	cases := []struct {
		TTL         time.Duration
		expectedTTL time.Duration
	}{
		{
			expectedTTL: 24 * time.Hour,
		},
		{
			TTL:         5 * time.Second,
			expectedTTL: 5 * time.Second,
		},
	}

	for i, c := range cases {
		lti := LDAPTokenIssuer{
			LDAPServer: "some-ldap-server",
			TTL:        c.TTL,
		}

		tok := lti.createToken(e)
		now := time.Now().UnixNano() / int64(time.Millisecond)
		expectedExpiration := now + int64(time.Duration(c.TTL)/time.Millisecond)

		if tok.Expiration > expectedExpiration {
			t.Errorf("Case: %d. Expiration expected: %d, got: %d", i, tok.Expiration, expectedExpiration)
		}
	}
}

func TestTokenExpired(t *testing.T) {
	e := &ldap.Entry{
		DN: "some-dn",
	}

	cases := []struct {
		TTL                  time.Duration
		sleep                time.Duration
		expectedTokenExpired bool
	}{
		{
			TTL:                  200 * time.Millisecond,
			sleep:                100 * time.Millisecond,
			expectedTokenExpired: false,
		},
		{
			TTL:                  200 * time.Millisecond,
			sleep:                300 * time.Millisecond,
			expectedTokenExpired: true,
		},
	}

	for i, c := range cases {
		lti := LDAPTokenIssuer{
			LDAPServer: "some-ldap-server",
			TTL:        c.TTL,
		}

		tok := lti.createToken(e)

		time.Sleep(c.sleep)
		tokenExpired := token.TokenExpired(tok)

		if tokenExpired != c.expectedTokenExpired {
			t.Errorf("case %d. Expected: %v, Got: %v", i, c.expectedTokenExpired, tokenExpired)
		}
	}
}
