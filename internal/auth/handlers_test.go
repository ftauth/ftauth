package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ftauth/ftauth/internal/config"
	"github.com/ftauth/ftauth/internal/database"
	"github.com/ftauth/ftauth/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_handleAuthorizationRequestError(t *testing.T) {
	redirectURI := "http://localhost:8080"
	requestErr := model.AuthorizationRequestErrInvalidRequest

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/authorize", nil)

	state := "state"
	handleAuthorizationRequestError(w, r, redirectURI, state, requestErr, model.RequestErrorDetails{
		ParamName: paramCodeChallenge,
		Details:   "Code challenge not provided",
	})

	loc := w.Header().Get("Location")

	var uri *url.URL
	uri, err := url.Parse(loc)
	require.NoError(t, err)

	query := uri.Query()
	assert.NotEmpty(t, query.Get("error"))
	assert.NotEmpty(t, query.Get("error_description"))
	assert.NotEmpty(t, query.Get("error_uri"))
}

func Test_handleTokenRequestError(t *testing.T) {
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

	db, err := database.InitializeBadgerDB(database.Options{InMemory: true, SeedDB: true})
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
				Path: "/authorize",
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
