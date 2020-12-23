package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/dnys1/ftoauth/internal/model"
	"github.com/stretchr/testify/require"
)

func Test_handleAuthorizationRequestError(t *testing.T) {
	redirectURI := "http://localhost:8080"
	requestErr := model.AuthorizationRequestErrInvalidRequest

	w := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodGet, "/authorize", nil)
	require.NoError(t, err)

	state := "state"
	handleAuthorizationRequestError(w, r, redirectURI, state, requestErr, model.RequestErrorDetails{
		ParamName: paramCodeChallenge,
		Details:   "Code challenge not provided",
	})

	loc := w.Header().Get("Location")

	var uri *url.URL
	uri, err = url.Parse(loc)
	require.NoError(t, err)

	query := uri.Query()
	require.NotEmpty(t, query.Get("error"))
	require.NotEmpty(t, query.Get("error_description"))
	require.NotEmpty(t, query.Get("error_uri"))
}
