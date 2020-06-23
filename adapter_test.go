package jwtauthhandler

import (
	"net/http/httptest"
	"testing"
)

func TestReadJwks(t *testing.T) {
	srv := httptest.NewServer(mockjwksResponse(t))
	jwtHandler, _ := CreateJwtHandler(srv.URL)
	defer srv.Close()
	jwksResponse, err := jwtHandler.readJwks()

	if err != nil {
		t.Errorf("No error should occur %v", err)
		t.FailNow()
	}
	if len(jwksResponse.Keys) != 2 {
		t.Errorf("response should contain exactly two keys")
		t.FailNow()
	}
}

func TestErrorResponse(t *testing.T) {
	srv := httptest.NewServer(mockErrorResponse())
	jwtHandler, _ := CreateJwtHandler(srv.URL)
	defer srv.Close()
	_, err := jwtHandler.readJwks()
	if err == nil {
		t.Error("should throw error")
		t.FailNow()
	}

}
