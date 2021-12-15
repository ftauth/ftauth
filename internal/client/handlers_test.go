package client

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ftauth/ftauth/internal/config"
	"github.com/ftauth/ftauth/internal/database"
	"github.com/ftauth/ftauth/pkg/model"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

func TestDynamicClientRegistration(t *testing.T) {
	config.LoadConfig()

	db, err := database.NewBadgerDB(true, nil)
	require.NoError(t, err)

	r := mux.NewRouter()
	SetupRoutes(r, db)

	tt := []struct {
		name          string
		clientRequest model.ClientRegistrationRequest
		statusCode    int
		predicates    func(client model.ClientInfo)
	}{
		{
			name:          "Empty Request",
			clientRequest: model.ClientRegistrationRequest{},
			statusCode:    http.StatusBadRequest,
		},
		{
			name: "Valid Public",
			clientRequest: model.ClientRegistrationRequest{
				Name:         "example",
				Type:         model.ClientTypePublic,
				RedirectURIs: []string{"localhost"},
				Scopes:       []string{"default"},
			},
			statusCode: http.StatusOK,
		},
		{
			name: "Valid Confidential",
			clientRequest: model.ClientRegistrationRequest{
				Name:         "example",
				Type:         model.ClientTypeConfidential,
				RedirectURIs: []string{"localhost"},
				Scopes:       []string{"default"},
			},
			statusCode: http.StatusOK,
		},
		{
			name: "Cannot Request admin scope",
			clientRequest: model.ClientRegistrationRequest{
				Name:         "example",
				Type:         model.ClientTypeConfidential,
				RedirectURIs: []string{"localhost"},
				Scopes:       []string{"default", "admin", "AdMiN"},
			},
			statusCode: http.StatusOK,
			predicates: func(client model.ClientInfo) {
				require.Equal(t, 1, len(client.Scopes))
				require.Equal(t, "default", client.Scopes[0].Name)
			},
		},
	}

	for _, test := range tt {
		t.Run(test.name, func(t *testing.T) {
			body, err := json.Marshal(test.clientRequest)
			require.NoError(t, err)
			req := httptest.NewRequest(
				http.MethodPost,
				"/client/register",
				bytes.NewReader(body),
			)

			resp := httptest.NewRecorder()

			r.ServeHTTP(resp, req)
			require.Equal(t, resp.Result().StatusCode, test.statusCode)

			if test.statusCode == http.StatusOK {
				var client model.ClientInfo
				err := json.NewDecoder(resp.Body).Decode(&client)
				require.NoError(t, err)

				err = client.IsValid()
				require.NoError(t, err)

				require.NotEmpty(t, client.ID)
				require.NotEmpty(t, client.GrantTypes)
				require.NotEmpty(t, client.JWKsURI)
				require.NotEmpty(t, client.AccessTokenLife)
				require.NotEmpty(t, client.RefreshTokenLife)
				if client.Type == model.ClientTypeConfidential {
					require.NotEmpty(t, client.Secret)
				}

				if test.predicates != nil {
					test.predicates(client)
				}
			}
		})
	}
}
