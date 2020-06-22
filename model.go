package jwtauthhandler

type JwtHandler struct {
	OpenIdProviderEndpoint string
}

type jwks struct {
	keys []key `json:"keys"`
}

type key struct {
	Use  string `json:"use"`
	Kty  string `json:"kty"`
	Kid  string `json:"kid"`
	Alg  string `json:"alg"`
	Nstr string `json:"n"`
	Estr string `json:"e"`
}
