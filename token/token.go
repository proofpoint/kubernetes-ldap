package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	jose "gopkg.in/square/go-jose.v1"
)

const (
	curveName = "P-256"    // curveName is the name of the ECDSA curve
	curveJose = jose.ES256 // curveJose is the name of the JWS algorithm
)

var curveEll = elliptic.P256()

// AuthToken contains information about the authenticated user
type AuthToken struct {
	Username   string
	Groups     []string
	Assertions map[string]string
	Expiration int64
}

const fileprefix = "signing"

func getPrivateKeyFilename(dirname string) string {
	return filepath.Join(dirname, fmt.Sprintf("%s.%s", fileprefix, "priv"))
}

func getPublicKeyFilename(dirname string) string {
	return filepath.Join(dirname, fmt.Sprintf("%s.%s", fileprefix, "pub"))
}

//KeypairExists checks if keypair exists already
func KeypairExists(dirname string) bool {
	_, err1 := ioutil.ReadFile(getPrivateKeyFilename(dirname))
	_, err2 := ioutil.ReadFile(getPublicKeyFilename(dirname))
	return (err1 == nil && err2 == nil)
}

// GenerateKeypair generates a public and private ECDSA key, to be
// used for signing and verifying authentication tokens.
func GenerateKeypair(dirname string) (err error) {
	privateFile := getPrivateKeyFilename(dirname)
	publicFile := getPublicKeyFilename(dirname)

	priv, err := ecdsa.GenerateKey(curveEll, rand.Reader)
	if err != nil {
		return
	}
	keyPEM, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(privateFile, keyPEM, os.FileMode(0600))
	if err != nil {
		return
	}
	pub := priv.Public()
	pubKeyPEM, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("Error marshalling public key: %v", err)
	}
	err = ioutil.WriteFile(publicFile, pubKeyPEM, os.FileMode(0644))
	return
}
