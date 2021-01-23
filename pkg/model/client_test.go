package model_test

import (
	"testing"

	"github.com/ftauth/ftauth/internal/mock"
	"github.com/ftauth/ftauth/pkg/model"
	"github.com/stretchr/testify/assert"
)

func TestIsValidRedirectURI(t *testing.T) {
	devClient := mock.PublicClient
	prodClient := mock.PublicClient
	prodClient.RedirectURIs = []string{"myapp://auth"}
	tt := []struct {
		client      model.ClientInfo
		redirectURI string
		valid       bool
	}{
		{
			client:      devClient,
			redirectURI: "http://localhost:8080/auth",
			valid:       true,
		},
		{
			client:      devClient,
			redirectURI: "http://localhost/auth",
			valid:       true,
		},
		{
			client:      devClient,
			redirectURI: "http://www.localhost.com/auth",
			valid:       false,
		},
		{
			client:      devClient,
			redirectURI: "http://www.localhost/auth",
			valid:       false,
		},
		{
			client:      devClient,
			redirectURI: "https://www.example.com/auth",
			valid:       false,
		},
		{
			client:      prodClient,
			redirectURI: "http://localhost:8080/auth",
			valid:       false,
		},
		{
			client:      prodClient,
			redirectURI: "http://localhost/auth",
			valid:       false,
		},
		{
			client:      prodClient,
			redirectURI: "http://www.localhost.com/auth",
			valid:       false,
		},
		{
			client:      prodClient,
			redirectURI: "http://www.localhost/auth",
			valid:       false,
		},
		{
			client:      prodClient,
			redirectURI: "https://www.example.com/auth",
			valid:       false,
		},
		{
			client:      prodClient,
			redirectURI: "myapp://auth",
			valid:       true,
		},
	}

	for _, test := range tt {
		got := test.client.IsValidRedirectURI(test.redirectURI)
		assert.Equalf(t, test.valid, got, "%s: Got %v Want %v", test.redirectURI, got, test.valid)
	}
}

func TestValidateScopes(t *testing.T) {
	tt := []struct {
		client model.ClientInfo
		scopes string
		valid  bool
	}{
		{
			client: mock.AdminClient,
			scopes: "default",
			valid:  true,
		},
		{
			client: mock.AdminClient,
			scopes: "admin",
			valid:  true,
		},
		{
			client: mock.AdminClient,
			scopes: "default admin",
			valid:  true,
		},
		{
			client: mock.PublicClient,
			scopes: "scope",
			valid:  false,
		},
		{
			client: mock.PublicClient,
			scopes: "default admin",
			valid:  false,
		},
		{
			client: mock.PublicClient,
			scopes: "admin",
			valid:  false,
		},
	}

	for _, test := range tt {
		err := test.client.ValidateScopes(test.scopes)
		if test.valid {
			assert.NoErrorf(t, err, "Scopes valid: %q Got error %v Want no error", test.scopes, err)
		} else {
			assert.Errorf(t, err, "Scopes valid: %q Got no error Want error", test.scopes)
		}
	}
}

func TestIsValid(t *testing.T) {
	tt := []struct {
		name   string
		client model.ClientInfo
		valid  bool
	}{
		{
			name:   "Valid Public Client",
			client: mock.PublicClient,
			valid:  true,
		},
		{
			name:   "Valid Admin Client",
			client: mock.AdminClient,
			valid:  true,
		},
		{
			name:   "Valid Confidential Client",
			client: mock.ConfidentialClient,
			valid:  true,
		},
		{
			name: "Missing Secret",
			client: model.ClientInfo{
				Name:         "Invalid Client",
				Type:         model.ClientTypeConfidential,
				RedirectURIs: []string{"localhost"},
				Scopes: []*model.Scope{
					{Name: "default"},
				},
				GrantTypes: []model.GrantType{
					model.GrantTypeClientCredentials,
				},
				AccessTokenLife:  60 * 60,
				RefreshTokenLife: 60 * 60 * 24,
			},
			valid: false,
		},
		{
			name: "Missing RedirectURIs",
			client: model.ClientInfo{
				Name: "Invalid Client",
				Type: model.ClientTypePublic,
				Scopes: []*model.Scope{
					{Name: "default"},
				},
				GrantTypes: []model.GrantType{
					model.GrantTypeClientCredentials,
				},
				AccessTokenLife:  60 * 60,
				RefreshTokenLife: 60 * 60 * 24,
			},
			valid: false,
		},
		{
			name: "Missing Scopes",
			client: model.ClientInfo{
				Name:         "Invalid Client",
				Type:         model.ClientTypePublic,
				RedirectURIs: []string{"localhost"},
				GrantTypes: []model.GrantType{
					model.GrantTypeClientCredentials,
				},
				AccessTokenLife:  60 * 60,
				RefreshTokenLife: 60 * 60 * 24,
			},
			valid: false,
		},
		{
			name: "Missing Grant Types",
			client: model.ClientInfo{
				Name:         "Invalid Client",
				Type:         model.ClientTypePublic,
				RedirectURIs: []string{"localhost"},
				Scopes: []*model.Scope{
					{Name: "default"},
				},
				AccessTokenLife:  60 * 60,
				RefreshTokenLife: 60 * 60 * 24,
			},
			valid: false,
		},
		{
			name: "Missing Access Token Life",
			client: model.ClientInfo{
				Name:         "Invalid Client",
				Type:         model.ClientTypePublic,
				RedirectURIs: []string{"localhost"},
				Scopes: []*model.Scope{
					{Name: "default"},
				},
				GrantTypes: []model.GrantType{
					model.GrantTypeClientCredentials,
				},
				RefreshTokenLife: 60 * 60 * 24,
			},
			valid: false,
		},
		{
			name: "Missing Refresh Token Life",
			client: model.ClientInfo{
				Name:         "Invalid Client",
				Type:         model.ClientTypePublic,
				RedirectURIs: []string{"localhost"},
				Scopes: []*model.Scope{
					{Name: "default"},
				},
				GrantTypes: []model.GrantType{
					model.GrantTypeClientCredentials,
				},
				AccessTokenLife: 60 * 60,
			},
			valid: false,
		},
	}

	for _, test := range tt {
		t.Run(test.name, func(t *testing.T) {
			err := test.client.IsValid()
			if test.valid {
				assert.NoErrorf(t, err, "Got error: %v", err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestIsDevClient(t *testing.T) {
	prodClient := mock.PublicClient
	prodClient.RedirectURIs = []string{"myapp://auth"}

	tt := []struct {
		client      model.ClientInfo
		isDevClient bool
	}{
		{
			client:      mock.PublicClient,
			isDevClient: true,
		},
		{
			client:      prodClient,
			isDevClient: false,
		},
	}

	for _, test := range tt {
		assert.Equal(t, test.isDevClient, test.client.IsDevClient())
	}
}
