package jwtauthhandler

import (
	"testing"
)

func TestCreateJwtHandler(t *testing.T) {

	tests := []struct {
		name    string
		args    string
		want    JwtHandler
		wantErr bool
	}{
		{name: "create successful JwtHandler",
			args:    "http//somewhere.com",
			want:    JwtHandler{OpenIDProviderEndpoint: "http//somewhere.com"},
			wantErr: false},
		{name: "create JwtHandler without url",
			args:    "",
			want:    JwtHandler{},
			wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateJwtHandler(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateJwtHandler() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got.OpenIDProviderEndpoint != tt.want.OpenIDProviderEndpoint {
				t.Errorf("CreateJwtHandler() = %v, want %v", got, tt.want)
			}
		})
	}
}
