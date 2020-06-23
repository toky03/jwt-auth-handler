package jwtauthhandler

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
)

func (jwtHanlder *JwtHandler) readJwks() (jwks, error) {

	openIDProviderEndpoint := jwtHanlder.OpenIDProviderEndpoint + "/.well-known/jwks.json"

	req, err := http.Get(openIDProviderEndpoint)

	body, err := ioutil.ReadAll(req.Body)

	var jwks jwks
	err = json.Unmarshal(body, &jwks)
	return jwks, err
}
