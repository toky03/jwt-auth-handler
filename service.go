package jwtauthhandler

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/big"
)

func CreateJwtHandler(openIdProviderEndpoint string) (JwtHandler, error) {
	if openIdProviderEndpoint == "" {
		return JwtHandler{}, errors.New("Enpoint must be provided")
	}
	return JwtHandler{
		OpenIdProviderEndpoint: openIdProviderEndpoint,
	}, nil
}

func (jwtHandler *JwtHandler) ReadPublicKeys() []rsa.PublicKey {
	jwks, err := jwtHandler.readJwks()
	if err != nil {
		log.Printf("could not read jwks: %v", err)
	}

	tokens := make([]rsa.PublicKey, 0, len(jwks.keys))
	for _, token := range jwks.keys {
		tokens = append(tokens, jwtHandler.createCert(token))
	}
	return tokens
}

func (jwtHanlder *JwtHandler) createCert(key key) rsa.PublicKey {

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
	exponent := binary.BigEndian.Uint32(buffer.Bytes())
	if err != nil {
		log.Printf("could not read from decoded e: %v", err)
	}

	publicKey := rsa.PublicKey{N: n, E: int(exponent)}
	fmt.Printf("Size of token is %v \n", publicKey.Size())
	return publicKey

}
