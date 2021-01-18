package auth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/ftauth/ftauth/internal/config"
	"github.com/ftauth/ftauth/internal/database"
	"github.com/ftauth/ftauth/internal/token"
	"github.com/ftauth/ftauth/jwt"
	"github.com/ftauth/ftauth/model"
	"github.com/ftauth/ftauth/util/base64url"
	"github.com/gofrs/uuid"
	"github.com/gorilla/mux"
)

type jwtKey string
type dpopKey string

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
	paramError               = "error"
	paramErrorDescription    = "error_description"
	paramErrorURI            = "error_uri"

	// JwtContextKey allows attachment/retrieval of JWT tokens from contexts.
	JwtContextKey  jwtKey  = "jwt"
	dpopContextKey dpopKey = "dpop"
)

// SetupRoutes configures routing for the given mux.
func SetupRoutes(
	r *mux.Router,
	authorizationDB database.AuthorizationDB,
	authenticationDB database.AuthenticationDB,
	clientDB database.ClientDB,
) {
	mi := middlewareInjector{db: authorizationDB}
	dpopMiddleware := mi.DPoPAuthenticated()

	r.Handle(
		AuthorizationEndpoint,
		authorizationEndpointHandler{db: authorizationDB, clientDB: clientDB},
	)
	r.Handle(
		TokenEndpoint,
		dpopMiddleware(tokenEndpointHandler{db: authorizationDB, clientDB: clientDB}),
	)
	r.Handle(LoginEndpoint, loginEndpointHandler{authenticationDB, authorizationDB})
	r.Handle(RegisterEndpoint, registerHandler{authenticationDB: authenticationDB})
}

type authorizationEndpointHandler struct {
	db       database.AuthorizationDB
	clientDB database.ClientDB
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
	clientInfo, err := h.clientDB.GetClient(ctx, clientID)

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
	// Check if client has single endpoint registered
	// If they do, use that
	// If not, consider this a required parameter
	redirectURI := query.Get(paramRedirectURI)
	if redirectURI == "" && len(clientInfo.RedirectURIs) == 1 {
		redirectURI = clientInfo.RedirectURIs[0]
	} else {
		// Verify redirect URI
		valid := false
		redirect, err := url.Parse(redirectURI)
		if err == nil {
			for _, uri := range clientInfo.RedirectURIs {
				if uri == model.LocalhostRedirectURI && redirect.Hostname() == model.LocalhostRedirectURI {
					valid = true
					break
				}
				if uri == redirectURI {
					valid = true
					break
				}
			}
		}
		if !valid {
			errorString := "Invalid redirect URI"
			if err != nil {
				errorString += fmt.Sprintf(": %v", err)
			}
			// Do not redirect to an unverified redirect URI
			http.Error(
				w,
				model.AuthorizationRequestErrInvalidRequest.Description(
					model.RequestErrorDetails{ParamName: paramRedirectURI, Details: errorString},
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
			return
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
		Expiry:              exp.Unix(),
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}

	// Create session from request, storing all required information
	ctx, cancel = context.WithTimeout(r.Context(), database.DefaultTimeout)
	defer cancel()

	sessionUUID, err := uuid.NewV4()
	if err != nil {
		handleAuthorizationRequestError(
			w, r, redirectURI, state,
			model.AuthorizationRequestErrServerError,
			model.RequestErrorDetails{},
		)
		return
	}
	sessionID := sessionUUID.String()
	authRequest.ID = sessionID

	err = h.db.CreateSession(ctx, authRequest)
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

	id, err := uuid.NewV4()
	if err != nil {
		log.Printf("Error generating UUID: %v\n", err)
		http.Error(w, "An unknown error occurred", http.StatusInternalServerError)
		return
	}
	err = h.authenticationDB.CreateUser(ctx, id.String(), username, password)
	if err != nil {
		log.Printf("Error creating user: %v\n", err)
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
	ctx, cancel = context.WithTimeout(r.Context(), database.DefaultTimeout)
	defer cancel()

	requestInfo, err := h.authorizationDB.GetRequestInfo(ctx, sessionID)
	if err != nil {
		http.Error(w, "Invalid session ID", http.StatusBadRequest)
		return
	}

	// Delete session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   0,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	if time.Unix(requestInfo.Expiry, 0).Before(time.Now()) {
		http.Error(w, "Session expired", http.StatusBadRequest)
		return
	}

	requestInfo.UserID = username

	ctx, cancel = context.WithTimeout(r.Context(), database.DefaultTimeout)
	defer cancel()

	err = h.authorizationDB.UpdateRequestInfo(ctx, requestInfo)
	if err != nil {
		log.Printf("Error saving request info: %v\n", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	redirect := fmt.Sprintf("%s?code=%s&state=%s", requestInfo.RedirectURI, requestInfo.Code, requestInfo.State)
	http.Redirect(w, r, redirect, http.StatusFound)
}

type tokenEndpointHandler struct {
	db       database.AuthorizationDB
	clientDB database.ClientDB
}

type tokenRequestInfo struct {
	scope  string
	userID string
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

	clientInfo, err := h.clientDB.GetClient(ctx, clientID)
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

	var validateRequestAndRetrieveScopes func(http.ResponseWriter, *http.Request, *model.ClientInfo) *tokenRequestInfo
	switch grantType {
	case model.GrantTypeAuthorizationCode:
		validateRequestAndRetrieveScopes = h.validateAuthorizationCodeRequest
	case model.GrantTypeRefreshToken:
		validateRequestAndRetrieveScopes = h.validateRefreshTokenRequest
	default:
		handleTokenRequestError(
			w,
			model.TokenRequestErrInvalidGrant,
			model.RequestErrorDetails{},
		)
		return
	}

	// validator handles error redirect
	reqInfo := validateRequestAndRetrieveScopes(w, r, clientInfo)
	if reqInfo == nil {
		return
	}

	// Generate access / refresh token
	// Try to send response to client:
	// 	If it fails, rollback changes in the database
	// 	to prevent token rotation without client involvement

	user := &model.User{ID: reqInfo.userID}
	accessToken, err := token.IssueAccessToken(clientInfo, user, reqInfo.scope)
	if err != nil {
		log.Printf("Error generating access token: %v\n", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	refreshToken, err := token.IssueRefreshToken(clientInfo, accessToken)
	if err != nil {
		log.Printf("Error generating refresh token: %v\n", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	tokenType := token.TypeBearer

	// Bind to DPoP key if DPoP request
	if dpop := r.Context().Value(dpopContextKey); dpop != nil {
		dpopToken, ok := dpop.(*jwt.Token)
		if !ok {
			log.Println("Context value expected to be DPoP")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		thumbprint, err := dpopToken.Header.JWK.Thumbprint()
		if err != nil {
			log.Printf("Error thumbprinting DPoP JWT: %v\n", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		accessToken.Claims.Confirmation = &jwt.ConfirmationClaim{
			SHA256Thumbprint: thumbprint,
		}
		refreshToken.Claims.Confirmation = &jwt.ConfirmationClaim{
			SHA256Thumbprint: thumbprint,
		}
		tokenType = token.TypeDPoP
	}

	accessJWT, err := accessToken.Encode(config.Current.OAuth.Tokens.PrivateKey)
	if err != nil {
		log.Printf("Error encoding access token: %v\n", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	refreshJWT, err := refreshToken.Encode(config.Current.OAuth.Tokens.PrivateKey)
	if err != nil {
		log.Printf("Error encoding refresh token: %v\n", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	response := model.TokenResponse{
		AccessToken:  accessJWT,
		TokenType:    tokenType,
		RefreshToken: refreshJWT,
		ExpiresIn:    clientInfo.AccessTokenLife,
	}

	ctx, cancel = context.WithTimeout(r.Context(), database.DefaultTimeout)
	defer cancel()

	commit, rollback, err := h.db.RegisterTokens(ctx, accessToken, refreshToken)
	if err != nil {
		log.Printf("Error saving tokens to DB: %v\n", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	b, err := json.Marshal(&response)
	if err != nil {
		log.Printf("Error marshalling token response: %v\n", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(b)))
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

func (h tokenEndpointHandler) validateAuthorizationCodeRequest(w http.ResponseWriter, r *http.Request, clientInfo *model.ClientInfo) *tokenRequestInfo {
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
			return nil
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
		return nil
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
		return nil
	}

	// Retrieve code challenge from session
	ctx, cancel := context.WithTimeout(r.Context(), database.DefaultTimeout)
	defer cancel()

	session, err := h.db.LookupSessionByCode(ctx, code)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}

	// Refuse request if code is expired
	if time.Unix(session.Expiry, 0).Before(time.Now()) {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}

	// Compare stored code challenge with code verifier
	digest := sha256.Sum256([]byte(codeVerifier))
	comp := base64url.Encode(digest[:])
	if session.CodeChallenge != comp {
		handleTokenRequestError(
			w,
			model.TokenRequestErrInvalidRequest,
			model.RequestErrorDetails{
				ParamName: paramCodeVerifier,
				Details:   "Code verifier does not match previously supplied.",
			},
		)
		return nil
	}

	return &tokenRequestInfo{
		scope:  session.Scope,
		userID: session.UserID,
	}
}

func (h tokenEndpointHandler) validateRefreshTokenRequest(w http.ResponseWriter, r *http.Request, clientInfo *model.ClientInfo) *tokenRequestInfo {
	// REQUIRED
	refreshTokenEnc := r.FormValue(paramRefreshToken)
	if refreshTokenEnc == "" {
		handleTokenRequestError(
			w,
			model.TokenRequestErrInvalidGrant,
			model.RequestErrorDetails{},
		)
		return nil
	}

	refreshToken, err := jwt.Decode(refreshTokenEnc)
	if err != nil {
		handleTokenRequestError(
			w,
			model.TokenRequestErrInvalidGrant,
			model.RequestErrorDetails{},
		)
		return nil
	}

	// Check if token is expired
	expiry := time.Unix(refreshToken.Claims.ExpirationTime, 0)
	if expiry.Before(time.Now()) {
		handleTokenRequestError(
			w,
			model.TokenRequestErrInvalidGrant,
			model.RequestErrorDetails{
				Details: "token expired",
			},
		)
		return nil
	}

	// Validate refresh token against DPoP public key, if present
	if dpop := r.Context().Value(dpopContextKey); dpop != nil {
		dpopToken, ok := dpop.(*jwt.Token)
		if !ok {
			log.Println("Context value expected to be DPoP")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return nil
		}

		err = refreshToken.Verify(dpopToken.Header.JWK)
		if err != nil {
			handleTokenRequestError(
				w,
				model.TokenRequestErrInvalidGrant,
				model.RequestErrorDetails{},
			)
			return nil
		}
	}

	var userID string
	userInfo, ok := refreshToken.Claims.CustomClaims["userInfo"]
	if ok {
		userID, _ = userInfo.(map[string]interface{})["id"].(string)
	}
	return &tokenRequestInfo{
		scope:  refreshToken.Claims.Scope,
		userID: userID,
	}
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
	query.Add(paramError, string(err.(model.AuthorizationRequestError)))
	query.Add(paramErrorDescription, err.Description(details))
	query.Add(paramErrorURI, err.URI())
	query.Add(paramState, state)

	// url.URL cannot handle '#' values in path
	// e.g. localhost:8080/#/token results in
	// 	Path = "/"
	//	Fragment = "/token"
	uri := fmt.Sprintf("%s?%s", redirectURI, query.Encode())
	http.Redirect(w, r, uri, http.StatusFound)
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
