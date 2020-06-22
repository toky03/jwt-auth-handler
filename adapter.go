package jwtauthhandler

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
)

func (jwtHanlder *JwtHandler) readJwks() (jwks, error) {

	openIdProviderEndpoint := jwtHanlder.OpenIdProviderEndpoint + "/.well-known/jwks.json"

	req, err := http.Get(openIdProviderEndpoint)

	body, err := ioutil.ReadAll(req.Body)

	var jwks jwks
	err = json.Unmarshal(body, &jwks)
	return jwks, err
}
