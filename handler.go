package jwtauthhandler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

func (jwtHandler *JwtHandler) AuthMiddleware(next http.Handler) http.Handler {

	if jwtHandler == nil {
		panic("jwt Handler must be declared before used")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := strings.Split(r.Header.Get("Authorization"), "Baerer ")
		if len(authHeader) != 2 {
			fmt.Println("Malformed token")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Malformed Token"))
		} else {
			jwtToken := authHeader[1]
			// TODO eventuell ParseWithClaims verwenden

			rsaKeys := jwtHandler.ReadPublicKeys()
			var err error
			for index, rsaKey := range rsaKeys {
				token, errParse := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
						return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
					}
					fmt.Printf("loop number %v \n", index)
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
