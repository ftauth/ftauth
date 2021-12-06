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
		clientRequest model.ClientInfo
		statusCode    int
	}{
		{
			name:          "Empty Request",
			clientRequest: model.ClientInfo{},
			statusCode:    http.StatusBadRequest,
		},
		{
			name: "Valid Public",
			clientRequest: model.ClientInfo{
				Name:         "example",
				Type:         model.ClientTypePublic,
				RedirectURIs: []string{"localhost"},
				Scopes:       []*model.Scope{{Name: "default"}},
			},
			statusCode: http.StatusOK,
		},
		{
			name: "Valid Confidential",
			clientRequest: model.ClientInfo{
				Name:         "example",
				Type:         model.ClientTypeConfidential,
				RedirectURIs: []string{"localhost"},
				Scopes:       []*model.Scope{{Name: "default"}},
			},
			statusCode: http.StatusOK,
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

				require.NotEmpty(t, client.ID)
				require.NotEmpty(t, client.GrantTypes)
				require.NotEmpty(t, client.JWKsURI)
				require.NotEmpty(t, client.AccessTokenLife)
				require.NotEmpty(t, client.RefreshTokenLife)
				if client.Type == model.ClientTypeConfidential {
					require.NotEmpty(t, client.Secret)
				}
			}
		})
	}
}
