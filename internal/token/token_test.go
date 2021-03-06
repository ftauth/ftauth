package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/ftauth/ftauth/internal/config"
	"github.com/ftauth/ftauth/internal/mock"
	"github.com/ftauth/ftauth/pkg/jwt"
	"github.com/ftauth/ftauth/pkg/model"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIssueAccessToken(t *testing.T) {
	config.LoadConfig()

	tt := []struct {
		name    string
		client  *model.ClientInfo
		user    *model.User
		scope   string
		wantErr bool
	}{
		{
			name:    "Missing client user scope",
			client:  nil,
			user:    nil,
			scope:   "",
			wantErr: true,
		},
		{
			name:    "Missing user scope",
			client:  &mock.PublicClient,
			user:    nil,
			scope:   "",
			wantErr: true,
		},
		{
			name:    "Missing scope",
			client:  &mock.PublicClient,
			user:    &model.User{ID: "test"},
			scope:   "",
			wantErr: true,
		},
		{
			name:    "Invalid user",
			client:  &mock.PublicClient,
			user:    &model.User{},
			scope:   "default",
			wantErr: true,
		},
		{
			name:    "Invalid scope",
			client:  &mock.PublicClient,
			user:    &model.User{ID: "test"},
			scope:   "àáa3",
			wantErr: true,
		},
		{
			name:    "Valid request",
			client:  &mock.PublicClient,
			user:    &model.User{ID: "test"},
			scope:   "default",
			wantErr: false,
		},
		{
			name:   "Parse user",
			client: &mock.PublicClient,
			user: &model.User{
				ID:        "test",
				FirstName: "Dillon",
				LastName:  "Nys",
			},
			scope:   "default",
			wantErr: false,
		},
	}

	for _, test := range tt {
		t.Run(test.name, func(t *testing.T) {
			accessToken, err := IssueAccessToken(test.client, test.user, test.scope)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			ftauthClaims, ok := accessToken.Claims.CustomClaims[Namespace]
			require.Truef(t, ok, "Missing FTAuth claims in custom claims")

			ftauthMap, ok := ftauthClaims.(map[string]interface{})
			require.Truef(t, ok, "FTAuth claim is not a map")

			require.NotEmptyf(t, ftauthMap["client_id"], "FTAuth claim is missing client ID")
			if test.client.Type != model.ClientTypeConfidential {
				require.NotEmptyf(t, ftauthMap["user_id"], "FTAuth claim is missing user ID")
			}
		})
	}
}

func TestIssueRefreshToken(t *testing.T) {
	config.LoadConfig()

	tt := []struct {
		name        string
		client      *model.ClientInfo
		accessToken func() *jwt.Token
		wantErr     bool
	}{
		{
			name:   "Valid client token",
			client: &mock.PublicClient,
			accessToken: func() *jwt.Token {
				token, err := IssueAccessToken(&mock.PublicClient, &model.User{ID: "test"}, "default")
				require.NoError(t, err)

				return token
			},
			wantErr: false,
		},
		{
			name: "Invalid client",
			accessToken: func() *jwt.Token {
				token, err := IssueAccessToken(&mock.PublicClient, &model.User{ID: "test"}, "default")
				require.NoError(t, err)

				return token
			},
			wantErr: true,
		},
		{
			name:   "Invalid token",
			client: &mock.PublicClient,
			accessToken: func() *jwt.Token {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				id, err := uuid.NewV4()
				require.NoError(t, err)

				token := &jwt.Token{
					Header: &jwt.Header{
						Type:      jwt.TypeAccess,
						Algorithm: jwt.AlgorithmRSASHA256,
					},
					Claims: &jwt.Claims{
						Issuer:  config.Current.Server.Host,
						Subject: "test",
						JwtID:   id.String(),
					},
				}

				jwk, err := jwt.NewJWKFromECDSAPrivateKey(key)
				require.NoError(t, err)

				_, err = token.Encode(jwk)
				require.NoError(t, err)

				return token
			},
			wantErr: true,
		},
	}

	for _, test := range tt {
		t.Run(test.name, func(t *testing.T) {
			_, err := IssueRefreshToken(test.client, test.accessToken())
			if test.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
