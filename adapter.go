package jwtauthhandler

import (
	"encoding/json"
	"io"
	"net/http"
)

func (jwtHandler *JwtHandler) readJwks() (jwks, error) {

	openIDProviderEndpoint := jwtHandler.OpenIDProviderEndpoint

	req, err := http.Get(openIDProviderEndpoint)

	body, err := io.ReadAll(req.Body)

	var jwks jwks
	err = json.Unmarshal(body, &jwks)
	return jwks, err
}
