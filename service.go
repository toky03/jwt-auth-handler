package jwtauthhandler

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"log"
	"math/big"

	"github.com/golang-jwt/jwt/v5"
)

// CreateJwtHandler initializes an new JwtHandler and exepts the endpoint of the openIDProvider
func CreateJwtHandler(openIDProviderEndpoint string) (JwtHandler, error) {
	if openIDProviderEndpoint == "" {
		return JwtHandler{}, errors.New("Enpoint must be provided")
	}
	return JwtHandler{
		OpenIDProviderEndpoint: openIDProviderEndpoint,
		ParseFunc:              jwt.Parse,
	}, nil
}

func (jwtHandler *JwtHandler) ReadPublicKeys() []rsa.PublicKey {
	jwks, err := jwtHandler.readJwks()
	if err != nil {
		log.Printf("could not read jwks: %v", err)
	}

	tokens := make([]rsa.PublicKey, 0, len(jwks.Keys))
	for _, token := range jwks.Keys {
		tokens = append(tokens, jwtHandler.createCert(token))
	}
	return tokens
}

func (jwtHandler *JwtHandler) createCert(key key) rsa.PublicKey {

	decN, err := base64.RawURLEncoding.DecodeString(key.Nstr)
	if err != nil {
		log.Printf("could not decode n: %v", err)
	}
	n := new(big.Int)
	n.SetBytes(decN)

	decE, err := base64.RawURLEncoding.DecodeString(key.Estr)
	if err != nil {
		log.Printf("could not decode e: %v", err)
	}

	var buffer bytes.Buffer
	buffer.WriteByte(0)
	buffer.Write(decE)
	var exponent int
	if len(buffer.Bytes()) > 2 {
		exponent = int(binary.BigEndian.Uint32(buffer.Bytes()))
	} else {
		exponent = int(binary.BigEndian.Uint16(buffer.Bytes()))
	}

	if err != nil {
		log.Printf("could not read from decoded e: %v", err)
	}

	publicKey := rsa.PublicKey{N: n, E: exponent}
	return publicKey

}
