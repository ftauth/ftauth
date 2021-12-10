package model_test

import (
	"testing"
	"time"

	"github.com/ftauth/ftauth/internal/mock"
	"github.com/ftauth/ftauth/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsValidRedirectURI(t *testing.T) {
	devClient := mock.PublicClient
	prodClient := mock.PublicClient
	prodClient.RedirectURIs = []string{
		"myapp://",
		"myapp://auth",
	}
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
		{
			client:      prodClient,
			redirectURI: "myapp://",
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
			scopes: "",
			valid:  false,
		},
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
			scopes: "",
			valid:  false,
		},
		{
			client: mock.PublicClient,
			scopes: "model.Scope",
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
			assert.NoErrorf(t, err, "model.Scopes valid: %q Got error %v Want no error", test.scopes, err)
		} else {
			assert.Errorf(t, err, "model.Scopes valid: %q Got no error Want error", test.scopes)
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
				Providers: []model.Provider{
					model.ProviderFTAuth,
				},
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
				Providers: []model.Provider{
					model.ProviderFTAuth,
				},
			},
			valid: false,
		},
		{
			name: "Missing model.Scopes",
			client: model.ClientInfo{
				Name:         "Invalid Client",
				Type:         model.ClientTypePublic,
				RedirectURIs: []string{"localhost"},
				GrantTypes: []model.GrantType{
					model.GrantTypeClientCredentials,
				},
				AccessTokenLife:  60 * 60,
				RefreshTokenLife: 60 * 60 * 24,
				Providers: []model.Provider{
					model.ProviderFTAuth,
				},
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
				Providers: []model.Provider{
					model.ProviderFTAuth,
				},
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
				Providers: []model.Provider{
					model.ProviderFTAuth,
				},
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
				Providers: []model.Provider{
					model.ProviderFTAuth,
				},
			},
			valid: false,
		},
		{
			name: "Missing Providers",
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
				AccessTokenLife:  60 * 60,
				RefreshTokenLife: 60 * 60 * 24,
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

func TestClientInfoGQL(t *testing.T) {
	id := "c44426d2-a3da-432e-829c-3bde3bc6f8c9"
	secret := "9dc86683-1fda-46b9-b9de-056b6c206158"
	secretExpiry := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	newName := "newName"
	jwksUri := "https://example.com/jwks.json"
	logoUri := "https://example.com/logo.png"
	accessTokenLife := 3600
	refreshTokenLife := 86400

	tt := []struct {
		name   string
		update model.ClientInfo
		want   string
	}{
		{
			name: "Complete info",
			update: model.ClientInfo{
				ID:           id,
				Name:         newName,
				Type:         model.ClientTypeConfidential,
				Secret:       secret,
				SecretExpiry: &secretExpiry,
				RedirectURIs: []string{
					"localhost",
					"myapp://auth",
				},
				JWKsURI: jwksUri,
				LogoURI: logoUri,
				Scopes: []*model.Scope{
					{Name: "default"},
					{Name: "admin"},
				},
				GrantTypes: []model.GrantType{
					model.GrantTypeAuthorizationCode,
					model.GrantTypeClientCredentials,
				},
				AccessTokenLife:  accessTokenLife,
				RefreshTokenLife: refreshTokenLife,
				Providers: []model.Provider{
					model.ProviderFTAuth,
					model.ProviderApple,
				},
			},
			want: `{id: "c44426d2-a3da-432e-829c-3bde3bc6f8c9"
name: "newName"
type: confidential
secret: "9dc86683-1fda-46b9-b9de-056b6c206158"
secret_expiry: "2021-01-01T00:00:00Z"
redirect_uris: ["localhost","myapp://auth"]
jwks_uri: "https://example.com/jwks.json"
logo_uri: "https://example.com/logo.png"
scopes: [{name:"default"},{name:"admin"}]
grant_types: [authorization_code,client_credentials]
access_token_life: 3600
refresh_token_life: 86400
providers: [ftauth,apple]}`,
		},
	}

	for _, test := range tt {
		t.Run(test.name, func(t *testing.T) {
			got := test.update.GQL()
			require.Equal(t, test.want, got)
		})
	}
}

func TestClientUpdateGQL(t *testing.T) {
	newName := "new name"
	jwksUri := "https://example.com/jwks.json"
	logoUri := "https://example.com/logo.png"
	accessTokenLife := 3600
	refreshTokenLife := 86400

	tt := []struct {
		name   string
		update model.ClientInfoUpdate
		want   string
	}{
		{
			name:   "Empty update",
			update: model.ClientInfoUpdate{},
			want:   "{}",
		},
		{
			name: "ID should not be included",
			update: model.ClientInfoUpdate{
				ID: "new ID",
			},
			want: "{}",
		},
		{
			name: "Complete update",
			update: model.ClientInfoUpdate{
				Name: &newName,
				RedirectURIs: &[]string{
					"localhost",
					"myapp://auth",
				},
				Scopes: &[]*model.Scope{
					{Name: "default"},
					{Name: "admin"},
				},
				JWKsURI:          &jwksUri,
				LogoURI:          &logoUri,
				AccessTokenLife:  &accessTokenLife,
				RefreshTokenLife: &refreshTokenLife,
				Providers: &[]model.Provider{
					model.ProviderFTAuth,
					model.ProviderApple,
				},
			},
			want: `{name: "new name"
redirect_uris: ["localhost","myapp://auth"]
scopes: [{name:"default"},{name:"admin"}]
jwks_uri: "https://example.com/jwks.json"
logo_uri: "https://example.com/logo.png"
access_token_life: 3600
refresh_token_life: 86400
providers: [ftauth,apple]
}`,
		},
	}

	for _, test := range tt {
		t.Run(test.name, func(t *testing.T) {
			got := test.update.GQL()
			require.Equal(t, test.want, got)
		})
	}
}
