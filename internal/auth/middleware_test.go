package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ftauth/ftauth/internal/config"
	"github.com/ftauth/ftauth/internal/database"
	fthttp "github.com/ftauth/ftauth/pkg/http"
	"github.com/ftauth/ftauth/pkg/jwt"
	"github.com/ftauth/ftauth/pkg/model"
	"github.com/ftauth/ftauth/pkg/oauth"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
)

func TestBearerAuthentated(t *testing.T) {
	config.LoadConfig()

	db, err := database.NewBadgerDB(true, nil)
	require.NoError(t, err)
	defer db.Close()

	handler := tokenEndpointHandler{db}

	id, err := uuid.NewV4()
	require.NoError(t, err)

	secret, err := uuid.NewV4()
	require.NoError(t, err)

	client := &model.ClientInfo{
		ID:     id.String(),
		Name:   "Confidential Client",
		Type:   model.ClientTypeConfidential,
		Secret: secret.String(),
		Scopes: []*model.Scope{{Name: "default"}},
		GrantTypes: []model.GrantType{
			model.GrantTypeClientCredentials,
			model.GrantTypeRefreshToken,
		},
		RedirectURIs:     []string{"localhost"},
		AccessTokenLife:  1,
		RefreshTokenLife: 1,
		Providers: []model.Provider{
			model.ProviderFTAuth,
		},
	}
	require.NoError(t, client.IsValid())

	_, err = db.RegisterClient(context.Background(), client, model.ClientOptionNone)
	require.NoError(t, err)

	mockClient := mockConfidentialClient{
		client:  client,
		handler: handler,
	}

	tt := []struct {
		name       string
		authHeader func(t *testing.T) string
		wantStatus int
	}{
		{
			name: "Empty",
			authHeader: func(*testing.T) string {
				return ""
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "Invalid token (Wrong JWK)",
			authHeader: func(*testing.T) string {
				accessToken, _ := mockClient.retrieveTokens(t)

				key, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)

				jwk, err := jwt.NewJWKFromRSAPrivateKey(key, jwt.AlgorithmRSASHA256)
				require.NoError(t, err)

				enc, err := accessToken.Encode(jwk)
				require.NoError(t, err)

				return "Bearer " + enc
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "Expired token",
			authHeader: func(t *testing.T) string {
				accessToken, _ := mockClient.retrieveTokens(t)
				accessTokenEnc, err := accessToken.Raw()
				require.NoError(t, err)

				<-time.After(6 * time.Second)

				return "Bearer " + accessTokenEnc
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "Valid token",
			authHeader: func(t *testing.T) string {
				accessToken, _ := mockClient.retrieveTokens(t)
				accessTokenEnc, err := accessToken.Raw()
				require.NoError(t, err)

				return "Bearer " + accessTokenEnc
			},
			wantStatus: http.StatusOK,
		},
	}

	m, err := fthttp.NewMiddleware(config.Current.JWKS(false))
	require.NoError(t, err)
	server := m.BearerAuthenticated(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	for _, test := range tt {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Header.Add("Authorization", test.authHeader(t))

			response := httptest.NewRecorder()

			server.ServeHTTP(response, request)

			require.Equal(t, test.wantStatus, response.Result().StatusCode)
		})
	}
}

func TestBearerAuthentatedWithScope(t *testing.T) {
	config.LoadConfig()

	db, err := database.NewBadgerDB(true, nil)
	require.NoError(t, err)
	defer db.Close()

	handler := tokenEndpointHandler{db}

	id, err := uuid.NewV4()
	require.NoError(t, err)

	secret, err := uuid.NewV4()
	require.NoError(t, err)

	client := &model.ClientInfo{
		ID:     id.String(),
		Name:   "Confidential Client",
		Type:   model.ClientTypeConfidential,
		Secret: secret.String(),
		Scopes: []*model.Scope{{Name: "default"}},
		GrantTypes: []model.GrantType{
			model.GrantTypeClientCredentials,
			model.GrantTypeRefreshToken,
		},
		RedirectURIs:     []string{"localhost"},
		AccessTokenLife:  1,
		RefreshTokenLife: 1,
		Providers: []model.Provider{
			model.ProviderFTAuth,
		},
	}
	require.NoError(t, client.IsValid())

	_, err = db.RegisterClient(context.Background(), client, model.ClientOptionNone)
	require.NoError(t, err)

	mockClient := mockConfidentialClient{
		client:  client,
		handler: handler,
	}

	tt := []struct {
		name       string
		authHeader func(t *testing.T) string
		scope      string
		wantStatus int
	}{
		{
			name: "Empty",
			authHeader: func(*testing.T) string {
				return ""
			},
			scope:      "default",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "Invalid token",
			authHeader: func(*testing.T) string {
				accessToken, _ := mockClient.retrieveTokens(t)

				key, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)

				jwk, err := jwt.NewJWKFromRSAPrivateKey(key, jwt.AlgorithmRSASHA256)
				require.NoError(t, err)

				enc, err := accessToken.Encode(jwk)
				require.NoError(t, err)

				return "Bearer " + enc
			},
			scope:      "default",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "Expired token",
			authHeader: func(t *testing.T) string {
				accessToken, _ := mockClient.retrieveTokens(t)
				accessTokenEnc, err := accessToken.Raw()
				require.NoError(t, err)

				<-time.After(6 * time.Second)

				return "Bearer " + accessTokenEnc
			},
			scope:      "default",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "Valid token",
			authHeader: func(t *testing.T) string {
				accessToken, _ := mockClient.retrieveTokens(t)
				accessTokenEnc, err := accessToken.Raw()
				require.NoError(t, err)

				return "Bearer " + accessTokenEnc
			},
			scope:      "default",
			wantStatus: http.StatusOK,
		},
		{
			name: "Invalid scope",
			authHeader: func(t *testing.T) string {
				accessToken, _ := mockClient.retrieveTokens(t)
				accessTokenEnc, err := accessToken.Raw()
				require.NoError(t, err)

				return "Bearer " + accessTokenEnc
			},
			scope:      "admin",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, test := range tt {
		t.Run(test.name, func(t *testing.T) {
			m, err := fthttp.NewMiddleware(config.Current.JWKS(false))
			require.NoError(t, err)
			middleware := m.BearerAuthenticatedWithScope(test.scope)
			server := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Header.Add("Authorization", test.authHeader(t))

			response := httptest.NewRecorder()

			server.ServeHTTP(response, request)

			require.Equal(t, test.wantStatus, response.Result().StatusCode)
		})
	}
}

func TestDPoPAuthenticated(t *testing.T) {
	config.LoadConfig()

	db, err := database.NewBadgerDB(true, nil)
	require.NoError(t, err)
	defer db.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privateJWK, err := jwt.NewJWKFromRSAPrivateKey(key, jwt.AlgorithmRSASHA256)
	require.NoError(t, err)

	publicJWK := privateJWK.PublicJWK()

	type testCase struct {
		name       string
		proof      func(t *testing.T) string
		wantStatus int
	}

	path := config.Current.Server.URL()

	tt := []testCase{
		{
			name: "Empty proof",
			proof: func(*testing.T) string {
				return ""
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "Invalid token (No Header JWK)",
			proof: func(*testing.T) string {
				id, err := uuid.NewV4()
				require.NoError(t, err)

				dpop := &jwt.Token{
					Header: &jwt.Header{
						Type:      jwt.TypeDPoP,
						Algorithm: jwt.AlgorithmPSSSHA256,
					},
					Claims: &jwt.Claims{
						JwtID:      id.String(),
						IssuedAt:   time.Now().Unix(),
						HTTPMethod: http.MethodGet,
						HTTPURI:    path,
					},
				}
				require.Error(t, dpop.Valid())

				enc, err := dpop.Encode(privateJWK)
				require.NoError(t, err)

				return enc
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "Invalid token (Mismatched JWK)",
			proof: func(*testing.T) string {
				id, err := uuid.NewV4()
				require.NoError(t, err)

				otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)

				otherJWK, err := jwt.NewJWKFromRSAPublicKey(&otherKey.PublicKey, jwt.AlgorithmRSASHA256)
				require.NoError(t, err)

				dpop := &jwt.Token{
					Header: &jwt.Header{
						Type:      jwt.TypeDPoP,
						Algorithm: jwt.AlgorithmPSSSHA256,
						JWK:       otherJWK,
					},
					Claims: &jwt.Claims{
						JwtID:      id.String(),
						IssuedAt:   time.Now().Unix(),
						HTTPMethod: http.MethodGet,
						HTTPURI:    path,
					},
				}
				require.NoError(t, dpop.Valid())

				enc, err := dpop.Encode(privateJWK)
				require.NoError(t, err)

				return enc
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "Old token",
			proof: func(t *testing.T) string {
				id, err := uuid.NewV4()
				require.NoError(t, err)

				dpop := &jwt.Token{
					Header: &jwt.Header{
						Type:      jwt.TypeDPoP,
						Algorithm: jwt.AlgorithmPSSSHA256,
						JWK:       publicJWK,
					},
					Claims: &jwt.Claims{
						JwtID:      id.String(),
						IssuedAt:   time.Now().Add(-11 * time.Minute).Unix(),
						HTTPMethod: http.MethodGet,
						HTTPURI:    path,
					},
				}
				require.NoError(t, dpop.Valid())

				enc, err := dpop.Encode(privateJWK)
				require.NoError(t, err)

				return enc
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "Invalid HTTP method",
			proof: func(t *testing.T) string {
				dpop, err := oauth.CreateProofToken(privateJWK, http.MethodPost, path)
				require.NoError(t, err)

				return dpop
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "Invalid HTTP URI",
			proof: func(t *testing.T) string {
				dpop, err := oauth.CreateProofToken(privateJWK, http.MethodGet, path+"/some-url")
				require.NoError(t, err)

				return dpop
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "Local (not absolute) HTTP URI",
			proof: func(t *testing.T) string {
				dpop, err := oauth.CreateProofToken(privateJWK, http.MethodGet, "/")
				require.NoError(t, err)

				return dpop
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "Valid token",
			proof: func(t *testing.T) string {
				dpop, err := oauth.CreateProofToken(privateJWK, http.MethodGet, path)
				require.NoError(t, err)

				return dpop
			},
			wantStatus: http.StatusOK,
		},
	}

	middlewareInjector := middlewareInjector{db}
	middleware := middlewareInjector.DPoPAuthenticated()
	server := middleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dpop := r.Context().Value(dpopContextKey)
		if dpop == nil {
			w.WriteHeader(http.StatusBadRequest)
		}
	}))

	for _, test := range tt {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			request.Header.Add("DPoP", test.proof(t))

			response := httptest.NewRecorder()

			server.ServeHTTP(response, request)

			require.Equal(t, test.wantStatus, response.Result().StatusCode)
		})
	}

	// Prevent token replay
	t.Run("Token replay", func(t *testing.T) {
		dpop, err := oauth.CreateProofToken(privateJWK, http.MethodGet, path)
		require.NoError(t, err)

		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Add("DPoP", dpop)

		response1 := httptest.NewRecorder()
		server.ServeHTTP(response1, request)
		require.Equal(t, http.StatusOK, response1.Result().StatusCode)

		response2 := httptest.NewRecorder()
		server.ServeHTTP(response2, request)
		require.Equal(t, http.StatusBadRequest, response2.Result().StatusCode)
	})
}
