package jwtauthhandler

import "github.com/dgrijalva/jwt-go"

// JwtHandler defines struct which acts as service
type JwtHandler struct {
	OpenIDProviderEndpoint string
	ParseFunc              func(string, jwt.Keyfunc) (*jwt.Token, error)
}

type jwks struct {
	Keys []key `json:"keys"`
}

type key struct {
	Use  string `json:"use"`
	Kty  string `json:"kty"`
	Kid  string `json:"kid"`
	Alg  string `json:"alg"`
	Nstr string `json:"n"`
	Estr string `json:"e"`
}
