package jwtauthhandler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestJwtHandler_AuthMiddleware(t *testing.T) {
	type createMockFunc struct {
		mockFunc func(*testing.T) http.HandlerFunc
	}
	type args struct {
		next http.Handler
	}
	tests := []struct {
		name      string
		header    string
		args      args
		mockFunc  createMockFunc
		want      string
		errorCode int
	}{
		{name: "Should validate successfully",
			args: args{
				next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Write([]byte("Works fine"))
				})},
			header:    "Bearer xyz.abc.def",
			mockFunc:  createMockFunc{mockFunc: mockjwksResponse},
			want:      "works fine",
			errorCode: http.StatusOK,
		},
		{name: "No Token should lead to unauthorized",
			args: args{
				next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Write([]byte("Works fine"))
				})},
			header:    "Bearer",
			mockFunc:  createMockFunc{mockFunc: mockjwksResponse},
			want:      "works fine",
			errorCode: http.StatusUnauthorized,
		},
	}
	for _, tt := range tests {
		srv := httptest.NewServer(tt.mockFunc.mockFunc(t))
		jwtHandler, _ := CreateJwtHandler(srv.URL)
		defer srv.Close()

		t.Run(tt.name, func(t *testing.T) {
			jwtHandler.ParseFunc = MockParse
			req, err := http.NewRequest("GET", "/", nil)
			req.Header.Add("Authorization", tt.header)
			if err != nil {
				t.Fatal(err)
			}

			rr := httptest.NewRecorder()
			handler := http.Handler(jwtHandler.AuthMiddleware(tt.args.next))
			handler.ServeHTTP(rr, req)
			if status := rr.Code; status != tt.errorCode {
				t.Errorf("Wrong error code. Expected %v got %v", tt.errorCode, status)
			}

		})
	}
}

func MockParse(tokenString string, keyFunc jwt.Keyfunc, parserOptions ...jwt.ParserOption) (*jwt.Token, error) {
	token := &jwt.Token{
		Valid:  true,
		Method: jwt.SigningMethodRS256}
	_, err := keyFunc(token)
	return token, err
}

func mockjwksResponse(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
		{
			"keys": [
			  {
				"use": "sig",
				"kty": "RSA",
				"kid": "public:Id1",
				"alg": "RS256",
				"n": "MzU",
				"e": "NQ"
			  },
			  {
				"use": "sig",
				"kty": "RSA",
				"kid": "public:Id2",
				"alg": "RS256",
				"n": "MzU",
				"e": "NQ"
			  }
			]
		  }
		`))
	}
}

func mockErrorResponse() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}
}
