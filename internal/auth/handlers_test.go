package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ftauth/ftauth/internal/config"
	"github.com/ftauth/ftauth/internal/database"
	"github.com/ftauth/ftauth/pkg/jwt"
	"github.com/ftauth/ftauth/pkg/model"
	"github.com/ftauth/ftauth/pkg/oauth"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleAuthorizationRequestError(t *testing.T) {
	redirectURI := "http://localhost:8080"
	requestErr := model.AuthorizationRequestErrInvalidRequest

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/authorize", nil)

	state := "state"
	handleAuthorizationRequestError(w, r, &authorizationRequestError{redirectURI, state, requestErr, model.RequestErrorDetails{
		ParamName: paramCodeChallenge,
		Details:   "Code challenge not provided",
	}})

	loc := w.Header().Get("Location")

	var uri *url.URL
	uri, err := url.Parse(loc)
	require.NoError(t, err)

	query := uri.Query()
	assert.NotEmpty(t, query.Get("error"))
	assert.NotEmpty(t, query.Get("error_description"))
	assert.NotEmpty(t, query.Get("error_uri"))
}

func TestHandleTokenRequestError(t *testing.T) {
	w := httptest.NewRecorder()

	handleTokenRequestError(
		w,
		model.TokenRequestErrInvalidClient,
		model.RequestErrorDetails{},
	)

	var resp map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp["error"])
}

func TestAuthorizationEndpoint(t *testing.T) {
	config.LoadConfig()

	db, err := database.InitializeBadgerDB(database.BadgerOptions{InMemory: true, SeedDB: true})
	defer db.Close()
	require.NoError(t, err)

	admin := db.AdminClient

	handler := authorizationEndpointHandler{
		db:       db,
		clientDB: db,
	}

	clientID := admin.ID
	state := "state"

	type want struct {
		statusCode int
		err        model.AuthorizationRequestError
		errDetails model.RequestErrorDetails
	}
	tt := []struct {
		name  string
		query map[string]string
		want  want
	}{
		{
			name:  "No client auth",
			query: map[string]string{},
			want: want{
				statusCode: http.StatusBadRequest,
				err:        model.AuthorizationRequestErrInvalidRequest,
				errDetails: model.RequestErrorDetails{
					ParamName: paramClientID,
				},
			},
		},
		{
			name: "Invalid: Redirect URI does not match",
			query: map[string]string{
				paramClientID:    clientID,
				paramRedirectURI: "https://example.com/token",
			},
			want: want{
				statusCode: http.StatusBadRequest,
				err:        model.AuthorizationRequestErrInvalidRequest,
				errDetails: model.RequestErrorDetails{
					ParamName: paramClientID,
				},
			},
		},
		{
			name: "Invalid: Missing redirect URI",
			query: map[string]string{
				paramClientID: clientID,
			},
			want: want{
				statusCode: http.StatusBadRequest,
				err:        model.AuthorizationRequestErrInvalidRequest,
				errDetails: model.RequestErrorDetails{
					ParamName: paramRedirectURI,
				},
			},
		},
		{
			name: "Invalid: Valid local redirect and missing state",
			query: map[string]string{
				paramClientID:    clientID,
				paramRedirectURI: "http://localhost:8080/token",
			},
			want: want{
				statusCode: http.StatusFound,
				err:        model.AuthorizationRequestErrInvalidRequest,
				errDetails: model.RequestErrorDetails{
					ParamName: paramState,
				},
			},
		},
		{
			name: "Invalid: Missing response type",
			query: map[string]string{
				paramClientID:     clientID,
				paramState:        state,
				paramRedirectURI:  "http://localhost:8080/token",
				paramResponseType: "",
			},
			want: want{
				statusCode: http.StatusFound,
				err:        model.AuthorizationRequestErrInvalidRequest,
				errDetails: model.RequestErrorDetails{
					ParamName: paramResponseType,
				},
			},
		},
		{
			name: "Invalid: Unknown response type",
			query: map[string]string{
				paramClientID:     clientID,
				paramState:        state,
				paramRedirectURI:  "http://localhost:8080/token",
				paramResponseType: "some_response_type",
			},
			want: want{
				statusCode: http.StatusFound,
				err:        model.AuthorizationRequestErrUnsupportedResponseType,
			},
		},
		{
			name: "Invalid: Invalid scope",
			query: map[string]string{
				paramClientID:     clientID,
				paramState:        state,
				paramRedirectURI:  "http://localhost:8080/token",
				paramResponseType: string(model.AuthorizationResponseTypeCode),
				paramScope:        "invalid_scope?!#$%^",
			},
			want: want{
				statusCode: http.StatusFound,
				err:        model.AuthorizationRequestErrInvalidScope,
			},
		},
		{
			name: "Invalid: Unknown scope",
			query: map[string]string{
				paramClientID:     clientID,
				paramState:        state,
				paramRedirectURI:  "http://localhost:8080/token",
				paramResponseType: string(model.AuthorizationResponseTypeCode),
				paramScope:        "non_default_scope",
			},
			want: want{
				statusCode: http.StatusFound,
				err:        model.AuthorizationRequestErrInvalidScope,
			},
		},
		{
			name: "Invalid: Missing code challenge",
			query: map[string]string{
				paramClientID:      clientID,
				paramState:         state,
				paramRedirectURI:   "http://localhost:8080/token",
				paramResponseType:  string(model.AuthorizationResponseTypeCode),
				paramCodeChallenge: "",
			},
			want: want{
				statusCode: http.StatusFound,
				err:        model.AuthorizationRequestErrInvalidRequest,
				errDetails: model.RequestErrorDetails{
					ParamName: paramCodeChallenge,
				},
			},
		},
		{
			name: "Invalid: Missing code challenge method",
			query: map[string]string{
				paramClientID:            clientID,
				paramState:               state,
				paramRedirectURI:         "http://localhost:8080/token",
				paramResponseType:        string(model.AuthorizationResponseTypeCode),
				paramCodeChallenge:       "code_challenge",
				paramCodeChallengeMethod: "",
			},
			want: want{
				statusCode: http.StatusFound,
				err:        model.AuthorizationRequestErrInvalidRequest,
				errDetails: model.RequestErrorDetails{
					ParamName: paramCodeChallengeMethod,
				},
			},
		},
		{
			name: "Invalid: Invalid code challenge method",
			query: map[string]string{
				paramClientID:            clientID,
				paramState:               state,
				paramRedirectURI:         "http://localhost:8080/token",
				paramResponseType:        string(model.AuthorizationResponseTypeCode),
				paramCodeChallenge:       "code_challenge",
				paramCodeChallengeMethod: string(model.CodeChallengeMethodPlain),
			},
			want: want{
				statusCode: http.StatusFound,
				err:        model.AuthorizationRequestErrInvalidRequest,
				errDetails: model.RequestErrorDetails{
					ParamName: paramCodeChallengeMethod,
				},
			},
		},
		{
			name: "Valid: Default scope/redirect requests",
			query: map[string]string{
				paramClientID:            clientID,
				paramState:               state,
				paramRedirectURI:         "http://localhost:8080/token",
				paramResponseType:        string(model.AuthorizationResponseTypeCode),
				paramCodeChallenge:       "code_challenge",
				paramCodeChallengeMethod: string(model.CodeChallengeMethodSHA256),
			},
			want: want{
				statusCode: http.StatusFound,
			},
		},
	}

	for _, test := range tt {
		t.Run(test.name, func(t *testing.T) {
			uri := url.URL{
				Path: AuthorizationEndpoint,
			}
			query := uri.Query()
			for key, val := range test.query {
				query.Set(key, val)
			}
			uri.RawQuery = query.Encode()
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, uri.String(), nil)

			handler.ServeHTTP(w, r)

			require.Equal(t, test.want.statusCode, w.Result().StatusCode, w.Body.String())
			switch w.Result().StatusCode {
			case http.StatusFound:
				if test.want.err != "" {
					uri, err := url.Parse(w.Header().Get("Location"))
					require.NoError(t, err)
					query := uri.Query()

					reqErr := model.AuthorizationRequestError(query.Get(paramError))
					assert.True(t, reqErr.IsValid())
					assert.Equal(t, test.want.err, reqErr)

					if reqErr == model.AuthorizationRequestErrInvalidRequest {
						errDesc := query.Get(paramErrorDescription)
						details := test.want.errDetails
						assert.True(t, strings.Contains(errDesc, "Invalid: "+details.ParamName))
					}
				} else {
					// Check redirect to login page
					assert.Equal(t, w.Header().Get("Location"), LoginEndpoint)

					// Check that session was created
					cookies := w.Result().Cookies()
					assert.NotEmpty(t, cookies)
				}
			}
		})
	}
}

func TestClientCredentialsGrant(t *testing.T) {
	config.LoadConfig()

	db, err := database.InitializeBadgerDB(database.BadgerOptions{InMemory: true, SeedDB: true})
	defer db.Close()
	require.NoError(t, err)

	handler := tokenEndpointHandler{
		db:       db,
		clientDB: db,
	}

	id, err := uuid.NewV4()
	require.NoError(t, err)

	secret, err := uuid.NewV4()
	require.NoError(t, err)

	client := &model.ClientInfo{
		ID:               id.String(),
		Name:             "Confidential Client",
		Type:             model.ClientTypeConfidential,
		Secret:           secret.String(),
		Scopes:           []*model.Scope{{Name: "default"}},
		GrantTypes:       []model.GrantType{model.GrantTypeClientCredentials},
		AccessTokenLife:  60 * 60,
		RefreshTokenLife: 24 * 60 * 60,
		Providers: []model.Provider{
			model.ProviderFTAuth,
		},
	}
	require.NoError(t, client.IsValid())

	_, err = db.RegisterClient(context.Background(), client, model.ClientOptionNone)
	require.NoError(t, err)

	tt := []struct {
		name         string
		clientID     string
		clientSecret string
		grantType    string
		scope        string
		wantStatus   int
	}{
		{
			name:         "Empty client ID",
			clientID:     "",
			clientSecret: "secret",
			grantType:    "client_credentials",
			scope:        "default",
			wantStatus:   http.StatusUnauthorized,
		},
		{
			name:         "Invalid client ID",
			clientID:     "d3790444-275c-48e5-9836-519cc1b78138",
			clientSecret: "secret",
			grantType:    "client_credentials",
			scope:        "default",
			wantStatus:   http.StatusUnauthorized,
		},
		{
			name:         "Invalid grant type",
			clientID:     id.String(),
			clientSecret: secret.String(),
			grantType:    string(model.GrantTypeAuthorizationCode),
			scope:        "",
			wantStatus:   http.StatusBadRequest,
		},
		{
			name:         "Empty scope",
			clientID:     id.String(),
			clientSecret: secret.String(),
			grantType:    "client_credentials",
			scope:        "",
			wantStatus:   http.StatusOK,
		},
		{
			name:         "Invalid scope",
			clientID:     id.String(),
			clientSecret: secret.String(),
			grantType:    "client_credentials",
			scope:        "admin",
			wantStatus:   http.StatusBadRequest,
		},
		{
			name:         "All valid values",
			clientID:     id.String(),
			clientSecret: secret.String(),
			grantType:    "client_credentials",
			scope:        "default",
			wantStatus:   http.StatusOK,
		},
	}

	for _, test := range tt {
		t.Run(test.name, func(t *testing.T) {
			vals := url.Values{
				paramGrantType: []string{test.grantType},
				paramScope:     []string{test.scope},
			}
			body := vals.Encode()

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, TokenEndpoint, strings.NewReader(body))

			r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Add("Content-Length", strconv.Itoa(len(body)))
			r.Header.Add("Authorization", oauth.CreateBasicAuthorization(test.clientID, test.clientSecret))

			handler.ServeHTTP(w, r)

			require.Equal(t, test.wantStatus, w.Result().StatusCode)
			if test.wantStatus != http.StatusOK {
				var response struct {
					Error            string `json:"error"`
					ErrorDescription string `json:"error_description"`
					ErrorURI         string `json:"error_uri"`
				}
				err := json.NewDecoder(w.Body).Decode(&response)
				require.NoError(t, err)

				require.NotEmpty(t, response.Error)
				require.NotEmpty(t, response.ErrorDescription)
				require.NotEmpty(t, response.ErrorURI)
			}
		})
	}
}

func TestResourceOwnerPasswordCredentialsGrant(t *testing.T) {
	config.LoadConfig()

	db, err := database.InitializeBadgerDB(database.BadgerOptions{InMemory: true, SeedDB: true})
	defer db.Close()
	require.NoError(t, err)

	handler := tokenEndpointHandler{
		db:       db,
		clientDB: db,
		authDB:   db,
	}

	id, err := uuid.NewV4()
	require.NoError(t, err)

	client := &model.ClientInfo{
		ID:               id.String(),
		Name:             "ROPC Client",
		Type:             model.ClientTypePublic,
		Scopes:           []*model.Scope{{Name: "default"}},
		GrantTypes:       []model.GrantType{model.GrantTypeResourceOwnerPasswordCredentials},
		RedirectURIs:     []string{"localhost"},
		AccessTokenLife:  60 * 60,
		RefreshTokenLife: 24 * 60 * 60,
		Providers: []model.Provider{
			model.ProviderFTAuth,
		},
	}
	require.NoError(t, client.IsValid())

	_, err = db.RegisterClient(context.Background(), client, model.ClientOptionNone)
	require.NoError(t, err)

	adminUsername := config.Current.OAuth.Admin.Username
	adminPassword := config.Current.OAuth.Admin.Password

	tt := []struct {
		name       string
		clientID   string
		grantType  string
		scope      string
		username   string
		password   string
		wantStatus int
	}{
		{
			name:       "Empty client ID",
			clientID:   "",
			grantType:  string(model.GrantTypeResourceOwnerPasswordCredentials),
			scope:      "default",
			username:   adminUsername,
			password:   adminPassword,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "Invalid client ID",
			clientID:   "5abbc545-6940-40b0-8aba-f448524739ef",
			grantType:  string(model.GrantTypeResourceOwnerPasswordCredentials),
			scope:      "default",
			username:   adminUsername,
			password:   adminPassword,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "Invalid grant type (authorization_code)",
			clientID:   client.ID,
			grantType:  string(model.GrantTypeAuthorizationCode),
			scope:      "default",
			username:   adminUsername,
			password:   adminPassword,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "Invalid grant type (client_credentials)",
			clientID:   client.ID,
			grantType:  string(model.GrantTypeClientCredentials),
			scope:      "default",
			username:   adminUsername,
			password:   adminPassword,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "Invalid grant type (refresh_token)",
			clientID:   client.ID,
			grantType:  string(model.GrantTypeRefreshToken),
			scope:      "default",
			username:   adminUsername,
			password:   adminPassword,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "Empty scope",
			clientID:   client.ID,
			grantType:  string(model.GrantTypeResourceOwnerPasswordCredentials),
			scope:      "",
			username:   adminUsername,
			password:   adminPassword,
			wantStatus: http.StatusOK,
		},
		{
			name:       "Invalid scope",
			clientID:   client.ID,
			grantType:  string(model.GrantTypeResourceOwnerPasswordCredentials),
			scope:      "random_scope",
			username:   adminUsername,
			password:   adminPassword,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "Invalid username",
			clientID:   client.ID,
			grantType:  string(model.GrantTypeResourceOwnerPasswordCredentials),
			scope:      "default",
			username:   "random_username",
			password:   adminPassword,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "Invalid password",
			clientID:   client.ID,
			grantType:  string(model.GrantTypeResourceOwnerPasswordCredentials),
			scope:      "default",
			username:   adminUsername,
			password:   "random_password_123",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "Valid login",
			clientID:   client.ID,
			grantType:  string(model.GrantTypeResourceOwnerPasswordCredentials),
			scope:      "default",
			username:   adminUsername,
			password:   adminPassword,
			wantStatus: http.StatusOK,
		},
	}

	for _, test := range tt {
		t.Run(test.name, func(t *testing.T) {
			vals := url.Values{
				paramGrantType: []string{test.grantType},
				paramScope:     []string{test.scope},
				paramUsername:  []string{test.username},
				paramPassword:  []string{test.password},
			}
			body := vals.Encode()

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, TokenEndpoint, strings.NewReader(body))

			r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Add("Content-Length", strconv.Itoa(len(body)))
			r.Header.Add("Authorization", oauth.CreateBasicAuthorization(test.clientID, ""))

			handler.ServeHTTP(w, r)

			require.Equal(t, test.wantStatus, w.Result().StatusCode)
			if test.wantStatus != http.StatusOK {
				var response struct {
					Error            string `json:"error"`
					ErrorDescription string `json:"error_description"`
					ErrorURI         string `json:"error_uri"`
				}
				err := json.NewDecoder(w.Body).Decode(&response)
				require.NoError(t, err)

				require.NotEmpty(t, response.Error)
				require.NotEmpty(t, response.ErrorDescription)
				require.NotEmpty(t, response.ErrorURI)
			}
		})
	}
}

func TestRefreshTokenGrant(t *testing.T) {
	config.LoadConfig()

	db, err := database.InitializeBadgerDB(database.BadgerOptions{InMemory: true, SeedDB: true})
	defer db.Close()
	require.NoError(t, err)

	handler := tokenEndpointHandler{
		db:       db,
		clientDB: db,
		authDB:   db,
	}

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
		AccessTokenLife:  60 * 60,
		RefreshTokenLife: 1,
		Providers: []model.Provider{
			model.ProviderFTAuth,
		},
	}
	require.NoError(t, client.IsValid())

	_, err = db.RegisterClient(context.Background(), client, model.ClientOptionNone)
	require.NoError(t, err)

	mockClient := mockConfidentialClient{
		t:       t,
		client:  client,
		handler: handler,
	}

	tt := []struct {
		name         string
		refreshToken func(t *testing.T) string
		wantStatus   int
	}{
		{
			name: "Valid refresh token",
			refreshToken: func(t *testing.T) string {
				_, refreshToken := mockClient.retrieveTokens()
				refreshTokenEnc, err := refreshToken.Raw()
				require.NoError(t, err)

				return refreshTokenEnc
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "Expired refresh token",
			refreshToken: func(t *testing.T) string {
				_, refreshToken := mockClient.retrieveTokens()
				refreshTokenEnc, err := refreshToken.Raw()
				require.NoError(t, err)

				<-time.After(1 * time.Second)
				return refreshTokenEnc
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "Invalid refresh token",
			refreshToken: func(t *testing.T) string {
				return ""
			},
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, test := range tt {
		t.Run(test.name, func(t *testing.T) {
			refreshToken := test.refreshToken(t)

			body := url.Values{}
			body.Set(paramGrantType, string(model.GrantTypeRefreshToken))
			body.Set(paramRefreshToken, refreshToken)
			enc := body.Encode()

			request := httptest.NewRequest(http.MethodPost, TokenEndpoint, strings.NewReader(enc))
			request.Header.Add("Authorization", oauth.CreateBasicAuthorization(client.ID, client.Secret))
			request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			request.Header.Add("Content-Length", strconv.Itoa(len(enc)))

			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			require.Equal(t, test.wantStatus, response.Result().StatusCode)
			if test.wantStatus == http.StatusOK {
				var resp model.TokenResponse
				err := json.NewDecoder(response.Body).Decode(&resp)
				require.NoError(t, err)

				_, err = jwt.Decode(resp.AccessToken)
				require.NoError(t, err)

				_, err = jwt.Decode(resp.RefreshToken)
				require.NoError(t, err)
			} else {
				var resp struct {
					Error       string `json:"error"`
					Description string `json:"error_description"`
					URI         string `json:"error_uri"`
				}

				err := json.NewDecoder(response.Body).Decode(&resp)
				require.NoError(t, err)

				require.NotEmpty(t, resp.Error)
				require.NotEmpty(t, resp.Description)
				require.NotEmpty(t, resp.URI)
			}
		})
	}
}

type mockConfidentialClient struct {
	client  *model.ClientInfo
	handler http.Handler
	t       *testing.T
}

func (mock mockConfidentialClient) retrieveTokens() (*jwt.Token, *jwt.Token) {
	body := url.Values{}
	body.Set(paramGrantType, string(model.GrantTypeClientCredentials))
	body.Set(paramScope, "default")
	enc := body.Encode()

	request := httptest.NewRequest(http.MethodPost, TokenEndpoint, strings.NewReader(enc))
	request.Header.Add("Authorization", oauth.CreateBasicAuthorization(mock.client.ID, mock.client.Secret))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(enc)))

	response := httptest.NewRecorder()

	mock.handler.ServeHTTP(response, request)

	require.Equal(mock.t, http.StatusOK, response.Result().StatusCode)

	var resp model.TokenResponse
	err := json.NewDecoder(response.Body).Decode(&resp)
	require.NoError(mock.t, err)

	accessToken, err := jwt.Decode(resp.AccessToken)
	require.NoError(mock.t, err)

	refreshToken, err := jwt.Decode(resp.RefreshToken)
	require.NoError(mock.t, err)

	return accessToken, refreshToken
}
