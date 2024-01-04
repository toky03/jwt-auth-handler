package jwtauthhandler

import "github.com/golang-jwt/jwt/v5"

// JwtHandler defines struct which acts as service
type JwtHandler struct {
	OpenIDProviderEndpoint string
	ParseFunc              func(string, jwt.Keyfunc, ...jwt.ParserOption) (*jwt.Token, error)
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
