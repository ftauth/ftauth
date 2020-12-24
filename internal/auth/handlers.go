package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/dnys1/ftoauth/internal/config"
	"github.com/dnys1/ftoauth/internal/database"
	"github.com/dnys1/ftoauth/internal/model"
	"github.com/dnys1/ftoauth/internal/token"
	"github.com/gorilla/mux"
)

const (
	// TokenEndpoint is used by the client to exchange
	// an authorization grant for an access token, typically
	// with client authentication.
	TokenEndpoint = "/token"

	// AuthorizationEndpoint is used by the client to obtain
	// authorization from the resource owner via user-agent
	// redirection.
	AuthorizationEndpoint = "/authorize"

	// LoginEndpoint is the endpoint for authenticating the user
	// with the authentication server.
	LoginEndpoint = "/login"

	// RegisterEndpoint is the endpoint for registering new users
	RegisterEndpoint = "/register"

	paramResponseType        = "response_type"
	paramClientID            = "client_id"
	paramScope               = "scope"
	paramState               = "state"
	paramRedirectURI         = "redirect_uri"
	paramGrantType           = "grant_type"
	paramCode                = "code"
	paramCodeChallenge       = "code_challenge"
	paramCodeChallengeMethod = "code_challenge_method"
	paramCodeVerifier        = "code_verifier"
	paramRefreshToken        = "refresh_token"
)

// SetupRoutes configures routing for the given mux.
func SetupRoutes(
	r *mux.Router,
	authorizationDB database.AuthorizationDB,
	authenticationDB database.AuthenticationDB,
) {
	r.Handle(AuthorizationEndpoint, authorizationEndpointHandler{authorizationDB})
	r.Handle(TokenEndpoint, tokenEndpointHandler{authorizationDB})
	r.Handle(LoginEndpoint, loginEndpointHandler{authenticationDB, authorizationDB})
	r.Handle(RegisterEndpoint, registerHandler{authenticationDB: authenticationDB})
}

type authorizationEndpointHandler struct {
	db database.AuthorizationDB
}

func (h authorizationEndpointHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query()

	// REQUIRED
	clientID := query.Get(paramClientID)

	// Get client info
	ctx, cancel := context.WithTimeout(r.Context(), database.DefaultTimeout)
	defer cancel()
	clientInfo, err := h.db.GetClientInfo(ctx, clientID)

	if clientID == "" || err != nil {
		// Even if the redirect URI is present, we should not redirect to it if
		// we cannot identify the client and confirm its registration.
		http.Error(
			w,
			model.AuthorizationRequestErrInvalidRequest.Description(
				model.RequestErrorDetails{ParamName: paramClientID, Details: "Invalid client ID"},
			),
			http.StatusBadRequest,
		)
		return
	}

	// OPTIONAL, but must be registered otherwise
	redirectURI := query.Get(paramRedirectURI)
	if redirectURI == "" {
		// Check if client has single endpoint registered
		// If they do, use that
		// If not, consider this a required parameter
		if len(clientInfo.RedirectURIs) == 1 {
			redirectURI = clientInfo.RedirectURIs[0]
		}
	} else {
		// Verify redirect URI
		valid := false
		for _, uri := range clientInfo.RedirectURIs {
			if uri == redirectURI {
				valid = true
				break
			}
		}
		if !valid {
			// Do not redirect to an unverified redirect URI
			http.Error(
				w,
				model.AuthorizationRequestErrInvalidRequest.Description(
					model.RequestErrorDetails{ParamName: paramRedirectURI, Details: "Invalid redirect URI"},
				),
				http.StatusBadRequest,
			)
			return
		}
	}

	// RECOMMENDED per RFC 6749
	// REQUIRED per FTOAuth
	state := query.Get(paramState)
	if state == "" {
		handleAuthorizationRequestError(
			w, r, redirectURI, state,
			model.AuthorizationRequestErrInvalidRequest,
			model.RequestErrorDetails{
				ParamName: paramState,
				Details:   "State required",
			},
		)
		return
	}

	// REQUIRED
	responseTypeStr := query.Get(paramResponseType)
	if responseTypeStr == "" {
		handleAuthorizationRequestError(
			w, r, redirectURI, state,
			model.AuthorizationRequestErrInvalidRequest,
			model.RequestErrorDetails{
				ParamName: paramResponseType,
				Details:   "Response type required",
			},
		)
		return
	}
	responseType := model.AuthorizationResponseType(responseTypeStr)
	if !responseType.IsValid() {
		handleAuthorizationRequestError(
			w, r, redirectURI, state,
			model.AuthorizationRequestErrUnsupportedResponseType,
			model.RequestErrorDetails{},
		)
		return
	}

	// OPTIONAL
	scope := query.Get(paramScope)
	if scope == "" {
		// Use default scope
		scope = config.Current.OAuth.Scopes.Default
	} else {
		err = clientInfo.ValidateScopes(scope)
		if err != nil {
			handleAuthorizationRequestError(
				w, r, redirectURI, state,
				model.AuthorizationRequestErrInvalidScope,
				model.RequestErrorDetails{},
			)
		}
	}

	// REQUIRED
	codeChallenge := query.Get(paramCodeChallenge)
	if codeChallenge == "" {
		handleAuthorizationRequestError(
			w, r, redirectURI, state,
			model.AuthorizationRequestErrInvalidRequest,
			model.RequestErrorDetails{
				ParamName: paramCodeChallenge,
				Details:   "Code challenge required",
			},
		)
		return
	}

	// REQUIRED
	codeChallengeMethodStr := query.Get(paramCodeChallengeMethod)
	if codeChallengeMethodStr == "" {
		handleAuthorizationRequestError(
			w, r, redirectURI, state,
			model.AuthorizationRequestErrInvalidRequest,
			model.RequestErrorDetails{
				ParamName: paramCodeChallengeMethod,
				Details:   "Code challenge method required",
			},
		)
		return
	}
	codeChallengeMethod := model.CodeChallengeMethod(codeChallengeMethodStr)
	if !codeChallengeMethod.IsValid() {
		handleAuthorizationRequestError(
			w, r, redirectURI, state,
			model.AuthorizationRequestErrInvalidRequest,
			model.RequestErrorDetails{
				ParamName: paramCodeChallengeMethod,
				Details:   "Transform algorithm is not supported",
			},
		)
		return
	}

	// Generate authorization request
	code := model.GenerateAuthorizationCode()
	exp := time.Now().Add(10 * time.Minute) // TODO: document

	authRequest := &model.AuthorizationRequest{
		ClientID:            clientID,
		Scope:               scope,
		State:               state,
		RedirectURI:         redirectURI,
		Code:                code,
		Expiry:              exp,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}

	// Create session from request, storing all required information
	ctx1, cancel1 := context.WithTimeout(r.Context(), database.DefaultTimeout)
	defer cancel1()

	sessionID, err := h.db.CreateSession(ctx1, authRequest)
	if err != nil {
		handleAuthorizationRequestError(
			w, r, redirectURI, state,
			model.AuthorizationRequestErrServerError,
			model.RequestErrorDetails{},
		)
		return
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	// Redirect to session login
	http.Redirect(w, r, LoginEndpoint, http.StatusFound)
}

type registerHandler struct {
	authenticationDB database.AuthenticationDB
}

func (h registerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.ServeFile(w, r, "template/register.html")
		return
	}

	// Parse form body for username and password
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "POST endpoint accepts valid form encoding only", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	if username == "" {
		http.Error(w, "Username cannot be empty", http.StatusBadRequest)
		return
	}
	password := r.FormValue("password")
	if password == "" {
		http.Error(w, "Password cannot be empty", http.StatusBadRequest)
		return
	}
	confirm := r.FormValue("confirm")
	if password != confirm {
		http.Error(w, "Passwords do not match", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), database.DefaultTimeout)
	defer cancel()

	err = h.authenticationDB.CreateUser(ctx, username, password)
	if err != nil {
		http.Error(w, "An unknown error occurred", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, LoginEndpoint, http.StatusFound)
}

type loginEndpointHandler struct {
	authenticationDB database.AuthenticationDB
	authorizationDB  database.AuthorizationDB
}

func (h loginEndpointHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.ServeFile(w, r, "template/index.html")
		return
	}

	// Parse form body for username and password
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "POST endpoint accepts valid form encoding only", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	if username == "" {
		http.Error(w, "Username cannot be empty", http.StatusBadRequest)
		return
	}
	password := r.FormValue("password")
	if password == "" {
		http.Error(w, "Password cannot be empty", http.StatusBadRequest)
		return
	}
	sessionCookie, err := r.Cookie("session")
	if err != nil {
		http.Error(w, "No session found for user", http.StatusBadRequest)
		return
	}
	sessionID := sessionCookie.Value
	if sessionID == "" {
		http.Error(w, "Invalid session ID", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), database.DefaultTimeout)
	defer cancel()

	err = h.authenticationDB.VerifyUsernameAndPassword(ctx, username, password)
	if err != nil {
		http.Error(w, "Invalid username and password", http.StatusBadRequest)
		return
	}

	// Get session information
	ctx1, cancel1 := context.WithTimeout(r.Context(), database.DefaultTimeout)
	defer cancel1()

	requestInfo, err := h.authorizationDB.GetRequestInfo(ctx1, sessionID)
	if err != nil {
		http.Error(w, "Invalid session ID", http.StatusBadRequest)
		return
	}

	redirect := fmt.Sprintf("%s?code=%s&state=%s", requestInfo.RedirectURI, requestInfo.Code, requestInfo.State)
	http.Redirect(w, r, redirect, http.StatusFound)
}

type tokenEndpointHandler struct {
	db database.AuthorizationDB
}

func (h tokenEndpointHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// RFC 6749 3.2: The client MUST use "POST" method when making access token requests.
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	handleHeaderErr := func(reason string) {
		handleTokenRequestError(w, model.TokenRequestErrInvalidClient, model.RequestErrorDetails{
			Details: reason,
		})
	}

	header := r.Header.Get("Authorization")
	if header == "" {
		handleHeaderErr("Authorization header not included")
		return
	}
	clientID, clientSecret, err := ParseBasicAuthorizationHeader(header)
	if err != nil {
		handleHeaderErr(err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), database.DefaultTimeout)
	defer cancel()

	clientInfo, err := h.db.GetClientInfo(ctx, clientID)
	if err != nil {
		handleHeaderErr("Could not locate client ID")
		return
	}

	// Verify client secret. OK if not present for public clients.
	validSecret := clientInfo.Secret == clientSecret
	if !validSecret {
		handleHeaderErr("Invalid client secret")
		return
	}

	// Parameters sent without a value MUST be treated as if they were omitted from the request.
	err = r.ParseForm()
	if err != nil {
		http.Error(w, "Invalid body format. Use application/x-www-form-urlencoded.", http.StatusBadRequest)
		return
	}

	grantTypeStr := r.FormValue(paramGrantType)
	if grantTypeStr == "" {
		handleTokenRequestError(
			w,
			model.TokenRequestErrInvalidRequest,
			model.RequestErrorDetails{
				ParamName: paramGrantType,
				Details:   "Grant type cannot be empty.",
			},
		)
	}
	grantType := model.GrantType(grantTypeStr)
	if !grantType.IsValid() {
		handleTokenRequestError(
			w,
			model.TokenRequestErrUnsupportedGrantType,
			model.RequestErrorDetails{},
		)
	}

	// OPTIONAL
	scope := r.FormValue(paramScope)
	if scope == "" {
		scope = config.Current.OAuth.Scopes.Default
	} else {
		err = clientInfo.ValidateScopes(scope)
		if err != nil {
			handleTokenRequestError(
				w,
				model.TokenRequestErrInvalidScope,
				model.RequestErrorDetails{},
			)
		}
	}

	var validator func(http.ResponseWriter, *http.Request, *model.ClientInfo) bool
	switch grantType {
	case model.GrantTypeAuthorizationCode:
		validator = h.validateAuthorizationCodeRequest
	case model.GrantTypeRefreshToken:
		validator = h.validateRefreshTokenRequest
	default:
		handleTokenRequestError(
			w,
			model.TokenRequestErrInvalidGrant,
			model.RequestErrorDetails{},
		)
		return
	}

	// validator handles error redirect
	if !validator(w, r, clientInfo) {
		return
	}

	// Generate access / refresh token
	// Try to send response to client:
	// 	If it fails, rollback changes in the database
	// 	to prevent token rotation without client involvement

	accessToken := token.IssueAccessToken(clientInfo, scope)
	refreshToken := token.IssueRefreshToken(clientInfo, accessToken)

	accessJWT, err := accessToken.Encode(config.Current.OAuth.Tokens.PrivateKey)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	refreshJWT, err := refreshToken.Encode(config.Current.OAuth.Tokens.PrivateKey)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	response := model.TokenResponse{
		AccessToken:  accessJWT,
		TokenType:    token.TypeJWT,
		RefreshToken: refreshJWT,
		ExpiresIn:    clientInfo.AccessTokenLife,
	}

	ctx, cancel = context.WithTimeout(r.Context(), database.DefaultTimeout)
	defer cancel()

	commit, rollback, err := h.db.RegisterTokens(ctx, accessToken, refreshToken)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	b, err := json.Marshal(&response)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	_, err = w.Write(b)
	if err != nil {
		err = rollback()
		if err != nil {
			log.Printf("Error rolling back: %v", err)
		}
	} else {
		err = commit()
		if err != nil {
			log.Printf("Error committing changes: %v", err)
		}
	}
}

func (h tokenEndpointHandler) validateAuthorizationCodeRequest(w http.ResponseWriter, r *http.Request, clientInfo *model.ClientInfo) bool {
	// REQUIRED
	clientID := r.FormValue(paramClientID)
	if clientID == "" {
		// Even if the redirect URI is present, we should not redirect to it if
		// we cannot identify the client and confirm its registration.
		http.Error(
			w,
			model.TokenRequestErrInvalidRequest.Description(
				model.RequestErrorDetails{ParamName: paramClientID, Details: "Client ID cannot be empty."},
			),
			http.StatusBadRequest,
		)
		return false
	}

	// REQUIRED, must match value from request
	redirectURI := r.FormValue(paramRedirectURI)
	if redirectURI == "" {
		// Verify redirect URI
		valid := false
		for _, uri := range clientInfo.RedirectURIs {
			if uri == redirectURI {
				valid = true
				break
			}
		}
		if !valid {
			// Do not redirect to an unverified redirect URI
			handleTokenRequestError(
				w,
				model.TokenRequestErrInvalidRequest,
				model.RequestErrorDetails{
					ParamName: paramRedirectURI,
					Details:   "Invalid redirectURI",
				},
			)
			return false
		}
	}

	// REQUIRED
	code := r.FormValue(paramCode)
	if code == "" {
		handleTokenRequestError(
			w,
			model.TokenRequestErrInvalidRequest,
			model.RequestErrorDetails{
				ParamName: paramCode,
				Details:   "Authorization code cannot be empty.",
			},
		)
		return false
	}

	// REQUIRED
	codeVerifier := r.FormValue(paramCodeVerifier)
	if codeVerifier == "" {
		handleTokenRequestError(
			w,
			model.TokenRequestErrInvalidRequest,
			model.RequestErrorDetails{
				ParamName: paramCodeVerifier,
				Details:   "Code verifier cannot be empty.",
			},
		)
		return false
	}

	// Retrieve code challenge from session
	ctx, cancel := context.WithTimeout(r.Context(), database.DefaultTimeout)
	defer cancel()

	session, err := h.db.LookupSessionByCode(ctx, code)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return false
	}

	// Compare stored code challenge with code verifier
	digest := sha256.Sum256([]byte(codeVerifier))
	comp := base64.URLEncoding.EncodeToString(digest[:])
	if session.CodeChallenge != comp {
		handleTokenRequestError(
			w,
			model.TokenRequestErrInvalidRequest,
			model.RequestErrorDetails{
				ParamName: paramCodeVerifier,
				Details:   "Code verifier does not match previously supplied.",
			},
		)
		return false
	}

	return true
}

func (h tokenEndpointHandler) validateRefreshTokenRequest(w http.ResponseWriter, r *http.Request, clientInfo *model.ClientInfo) bool {
	// REQUIRED
	refreshToken := r.FormValue(paramRefreshToken)
	if refreshToken == "" {
		handleTokenRequestError(
			w,
			model.TokenRequestErrInvalidGrant,
			model.RequestErrorDetails{},
		)
		return false
	}

	// Validate refresh token with database

	return true
}

func handleAuthorizationRequestError(
	w http.ResponseWriter,
	r *http.Request,
	redirectURI,
	state string,
	err model.RequestError,
	details model.RequestErrorDetails,
) {
	errorURI, _ := url.Parse(redirectURI)
	query := errorURI.Query()
	query.Add("error", string(err.(model.AuthorizationRequestError)))
	query.Add("error_description", err.Description(details))
	query.Add("error_uri", err.URI())
	query.Add("state", state)
	errorURI.RawQuery = query.Encode()
	http.Redirect(w, r, errorURI.String(), http.StatusFound)
}

func handleTokenRequestError(w http.ResponseWriter, reqErr model.TokenRequestError, details model.RequestErrorDetails) {
	res := struct {
		Error            model.TokenRequestError `json:"error"`
		ErrorDescription string                  `json:"error_description"`
		ErrorURI         string                  `json:"error_uri"`
	}{
		Error:            reqErr,
		ErrorDescription: reqErr.Description(details),
		ErrorURI:         reqErr.URI(),
	}

	b, err := json.Marshal(&res)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Required by the OAuth 2.0 protocol
	// RFC 6749 5.2
	if reqErr == model.TokenRequestErrInvalidClient {
		w.Header().Set("WWW-Authenticate", "Basic")
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(reqErr.StatusCode())
	w.Write(b)
}
