package auth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ftauth/ftauth/internal/config"
	"github.com/ftauth/ftauth/internal/database"
	"github.com/ftauth/ftauth/internal/templates"
	"github.com/ftauth/ftauth/internal/token"
	"github.com/ftauth/ftauth/pkg/jwt"
	"github.com/ftauth/ftauth/pkg/model"
	"github.com/ftauth/ftauth/pkg/util/base64url"
	"github.com/ftauth/ftauth/pkg/util/passwordutil"
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
	paramUsername            = "username"
	paramPassword            = "password"
	paramRefreshToken        = "refresh_token"
	paramProvider            = "provider"
	paramError               = "error"
	paramErrorDescription    = "error_description"
	paramErrorURI            = "error_uri"

	// Apple parameters
	paramIDToken = "id_token"
	paramUser    = "user"

	// JwtContextKey allows attachment/retrieval of JWT tokens from contexts.
	JwtContextKey  jwtKey  = "jwt"
	dpopContextKey dpopKey = "dpop"

	// Recommended authorization code lifetime
	sessionExp = 10 * time.Minute
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
		dpopMiddleware(tokenEndpointHandler{db: authorizationDB, clientDB: clientDB, authDB: authenticationDB}),
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

	provider := model.Provider(query.Get(paramProvider))
	if provider == "" {
		provider = model.ProviderFTAuth
	}

	var validator Validator
	switch provider {
	case model.ProviderFTAuth:
		validator = &ftauthValidator{h.clientDB}
	default:
		handleAuthorizationRequestError(w, r, &authorizationRequestError{
			err: model.AuthorizationRequestErrInvalidRequest,
			details: model.RequestErrorDetails{
				ParamName: paramProvider,
				Details:   fmt.Sprintf("Unsupported provider: %s", provider),
			},
		})
		return
	}

	authRequest, requestErr := validator.ValidateAuthorizationCodeRequest(r)
	if requestErr != nil {
		handleAuthorizationRequestError(w, r, requestErr)
		return
	}

	// Create session from request, storing all required information
	ctx, cancel := context.WithTimeout(r.Context(), database.DefaultTimeout)
	defer cancel()

	sessionUUID, err := uuid.NewV4()
	if err != nil {
		requestErr = &authorizationRequestError{
			authRequest.RedirectURI, authRequest.State,
			model.AuthorizationRequestErrServerError,
			model.RequestErrorDetails{},
		}
		handleAuthorizationRequestError(w, r, requestErr)
		return
	}
	sessionID := sessionUUID.String()
	authRequest.ID = sessionID

	err = h.db.CreateSession(ctx, authRequest)
	if err != nil {
		requestErr = &authorizationRequestError{
			authRequest.RedirectURI, authRequest.State,
			model.AuthorizationRequestErrServerError,
			model.RequestErrorDetails{},
		}
		handleAuthorizationRequestError(w, r, requestErr)
		return
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Path:     "/",
		Expires:  time.Now().Add(sessionExp),
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
		templates.All.ExecuteTemplate(w, "register", config.Current.OAuth.Template.Options)
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

	hash, err := passwordutil.GeneratePasswordHash(password)
	if err != nil {
		log.Printf("Error generating password hash: %v\n", err)
	}

	user := &model.User{
		ID:           id.String(),
		Username:     username,
		PasswordHash: hash,
	}
	err = h.authenticationDB.RegisterUser(ctx, user)
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
		templates.All.ExecuteTemplate(w, "login", config.Current.OAuth.Template.Options)
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
		log.Println("Username cannot be empty")
		http.Error(w, "Username cannot be empty", http.StatusBadRequest)
		return
	}
	password := r.FormValue("password")
	if password == "" {
		log.Println("Password cannot be empty")
		http.Error(w, "Password cannot be empty", http.StatusBadRequest)
		return
	}
	sessionCookie, err := r.Cookie("session")
	if err != nil {
		log.Println("No session found for user")
		http.Error(w, "No session found for user", http.StatusBadRequest)
		return
	}
	sessionID := sessionCookie.Value
	if sessionID == "" {
		log.Println("Could not retrieve session cookie")
		http.Error(w, "Invalid session ID", http.StatusBadRequest)
		return
	}

	// Get session information
	ctx, cancel := context.WithTimeout(r.Context(), database.DefaultTimeout)
	defer cancel()

	requestInfo, err := h.authorizationDB.GetRequestInfo(ctx, sessionID)
	if err != nil {
		log.Printf("Error retrieving request info: %v\n", err)
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

	if requestInfo.Expiry.Before(time.Now()) {
		http.Error(w, "Session expired", http.StatusBadRequest)
		return
	}

	ctx, cancel = context.WithTimeout(r.Context(), database.DefaultTimeout)
	defer cancel()

	err = h.authenticationDB.VerifyUsernameAndPassword(ctx, username, requestInfo.ClientID, password)
	if err != nil {
		log.Printf("Error validating user info: %v\n", err)
		http.Error(w, "Invalid username and password", http.StatusBadRequest)
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
	authDB   database.AuthenticationDB
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
	case model.GrantTypeClientCredentials:
		validateRequestAndRetrieveScopes = h.validateClientCredentialsRequest
	case model.GrantTypeResourceOwnerPasswordCredentials:
		validateRequestAndRetrieveScopes = h.validateResourceOwnerPasswordCredentialsRequest
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

	// validator handles error redirect, signaled by a nil return here
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
	}

	privateKey := config.Current.DefaultSigningKey()
	accessJWT, err := accessToken.Encode(privateKey)
	if err != nil {
		log.Printf("Error encoding access token: %v\n", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	refreshJWT, err := refreshToken.Encode(privateKey)
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

	b, err := json.Marshal(&response)
	if err != nil {
		log.Printf("Error marshalling token response: %v\n", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(b)))
	w.Write(b)
}

func (h tokenEndpointHandler) validateClientCredentialsRequest(w http.ResponseWriter, r *http.Request, clientInfo *model.ClientInfo) *tokenRequestInfo {
	// Other grant types could end up here. Let's validate the grant type.
	foundClientCredentialsGrantType := false
	for _, grantType := range clientInfo.GrantTypes {
		if grantType == model.GrantTypeClientCredentials {
			foundClientCredentialsGrantType = true
			break
		}
	}

	if clientInfo.Type != model.ClientTypeConfidential || !foundClientCredentialsGrantType {
		handleTokenRequestError(w, model.TokenRequestErrUnauthorizedClient, model.RequestErrorDetails{
			Details: "This client does not support the client credentials grant",
		})
		return nil
	}

	body := r.Form

	scope := body.Get(paramScope)
	if scope == "" {
		// Use default scope
		scope = config.Current.OAuth.Scopes.Default
	} else {
		err := clientInfo.ValidateScopes(scope)
		if err != nil {
			handleTokenRequestError(w, model.TokenRequestErrInvalidScope, model.RequestErrorDetails{
				ParamName: paramScope,
			})
			return nil
		}
	}

	return &tokenRequestInfo{
		scope:  scope,
		userID: clientInfo.ID,
	}
}

func (h tokenEndpointHandler) validateResourceOwnerPasswordCredentialsRequest(w http.ResponseWriter, r *http.Request, clientInfo *model.ClientInfo) *tokenRequestInfo {
	// Other grant types could end up here. Let's validate the grant type.
	foundClientCredentialsGrantType := false
	for _, grantType := range clientInfo.GrantTypes {
		if grantType == model.GrantTypeResourceOwnerPasswordCredentials {
			foundClientCredentialsGrantType = true
			break
		}
	}

	if !foundClientCredentialsGrantType {
		handleTokenRequestError(w, model.TokenRequestErrUnauthorizedClient, model.RequestErrorDetails{
			Details: "This client does not support the resource owner password credentials grant",
		})
		return nil
	}

	scope := r.Form.Get(paramScope)
	if scope == "" {
		// Use default scope
		scope = config.Current.OAuth.Scopes.Default
	} else {
		err := clientInfo.ValidateScopes(scope)
		if err != nil {
			handleTokenRequestError(w, model.TokenRequestErrInvalidScope, model.RequestErrorDetails{
				ParamName: paramScope,
			})
			return nil
		}
	}

	username := r.Form.Get(paramUsername)
	if username == "" {
		handleTokenRequestError(w, model.TokenRequestErrInvalidGrant, model.RequestErrorDetails{})
		return nil
	}
	password := r.Form.Get(paramPassword)
	if password == "" {
		handleTokenRequestError(w, model.TokenRequestErrInvalidGrant, model.RequestErrorDetails{})
		return nil
	}

	ctx, cancel := context.WithTimeout(r.Context(), database.DefaultTimeout)
	defer cancel()

	err := h.authDB.VerifyUsernameAndPassword(ctx, username, clientInfo.ID, password)
	if err != nil {
		handleTokenRequestError(w, model.TokenRequestErrInvalidGrant, model.RequestErrorDetails{})
		return nil
	}

	user, err := h.authDB.GetUserByUsername(ctx, username, clientInfo.ID)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}

	return &tokenRequestInfo{
		userID: user.ID,
		scope:  scope,
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
	if session.Expiry.Before(time.Now()) {
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

	var scopes []string
	for _, s := range session.Scope {
		scopes = append(scopes, s.Name)
	}
	return &tokenRequestInfo{
		scope:  strings.Join(scopes, " "),
		userID: session.UserID,
	}
}

func (h tokenEndpointHandler) validateRefreshTokenRequest(w http.ResponseWriter, r *http.Request, clientInfo *model.ClientInfo) *tokenRequestInfo {
	// Other grant types could end up here. Let's validate the grant type.
	foundClientCredentialsGrantType := false
	for _, grantType := range clientInfo.GrantTypes {
		if grantType == model.GrantTypeRefreshToken {
			foundClientCredentialsGrantType = true
			break
		}
	}

	if !foundClientCredentialsGrantType {
		handleTokenRequestError(w, model.TokenRequestErrUnauthorizedClient, model.RequestErrorDetails{
			Details: "This client does not support refreshing credentials",
		})
		return nil
	}

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
	requestErr *authorizationRequestError,
) {
	if requestErr.redirectURI != "" {
		errorURI, _ := url.Parse(requestErr.redirectURI)
		query := errorURI.Query()
		query.Add(paramError, string(requestErr.err))
		query.Add(paramErrorDescription, requestErr.err.Description(requestErr.details))
		query.Add(paramErrorURI, requestErr.err.URI())
		query.Add(paramState, requestErr.state)

		// url.URL cannot handle '#' values in path
		// e.g. localhost:8080/#/token results in
		// 	Path = "/"
		//	Fragment = "/token"
		uri := fmt.Sprintf("%s?%s", requestErr.redirectURI, query.Encode())
		http.Redirect(w, r, uri, http.StatusFound)
	} else {
		http.Error(w, requestErr.err.Description(requestErr.details), http.StatusBadRequest)
	}
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
