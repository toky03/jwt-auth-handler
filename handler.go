package jwtauthhandler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// AuthMiddleware acts as Middleware which validates an Auth token by validating the signature with the public key from the jwks endpoint
func (jwtHandler *JwtHandler) AuthMiddleware(next http.Handler) http.Handler {

	if jwtHandler == nil {
		panic("jwt Handler must be declared before used")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := strings.Split(r.Header.Get("Authorization"), "Bearer ")
		if len(authHeader) != 2 {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Malformed Token"))
		} else {
			jwtToken := authHeader[1]
			// TODO eventuell ParseWithClaims verwenden

			rsaKeys := jwtHandler.ReadPublicKeys()
			var err error
			for _, rsaKey := range rsaKeys {
				token, errParse := jwtHandler.ParseFunc(jwtToken, func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
						return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
					}
					return &rsaKey, nil
				})
				if token.Valid {
					break
				} else {
					err = errParse
				}
			}

			if err == nil {
				next.ServeHTTP(w, r)
			} else {
				fmt.Println(err)
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Unauthorized"))
			}

		}
	})
}
