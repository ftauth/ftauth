package auth

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/ftauth/ftauth/internal/config"
	"github.com/ftauth/ftauth/internal/database"
	"github.com/ftauth/ftauth/pkg/model"
)

type authorizationRequestError struct {
	redirectURI string
	state       string
	err         model.AuthorizationRequestError
	details     model.RequestErrorDetails
}

// Validator handles validation of a request
type Validator interface {
	ValidateAuthorizationCodeRequest(r *http.Request) (*model.AuthorizationRequest, *authorizationRequestError)
}

type ftauthValidator struct {
	clientDB database.ClientDB
}

func (v ftauthValidator) ValidateAuthorizationCodeRequest(r *http.Request) (*model.AuthorizationRequest, *authorizationRequestError) {
	// Even if the redirect URI is present, we should not redirect to it if
	// we cannot identify the client and confirm its registration.
	invalidClientID := &authorizationRequestError{
		err:     model.AuthorizationRequestErrInvalidRequest,
		details: model.RequestErrorDetails{ParamName: paramClientID, Details: "Invalid client ID"},
	}

	query := r.URL.Query()

	// REQUIRED
	clientID := query.Get(paramClientID)

	if clientID == "" {
		return nil, invalidClientID
	}

	// Get client info
	ctx, cancel := context.WithTimeout(r.Context(), database.DefaultTimeout)
	defer cancel()
	clientInfo, err := v.clientDB.GetClient(ctx, clientID)

	if err != nil {
		log.Printf("Error retrieving client ID %s: %v\n", clientID, err)
		return nil, invalidClientID
	}

	// OPTIONAL, but must be registered otherwise
	// Check if client has single endpoint registered
	// If they do, use that
	// If not, consider this a required parameter
	redirectURI := query.Get(paramRedirectURI)
	{
		// Verify redirect URI
		if !clientInfo.IsValidRedirectURI(redirectURI) {
			errorString := "Invalid redirect URI"
			if err != nil {
				errorString += fmt.Sprintf(": %v", err)
			}
			// Do not redirect to an unverified redirect URI
			return nil, &authorizationRequestError{
				err:     model.AuthorizationRequestErrInvalidRequest,
				details: model.RequestErrorDetails{ParamName: paramRedirectURI, Details: errorString},
			}
		}
	}

	// RECOMMENDED per RFC 6749
	// REQUIRED per FTAuth
	state := query.Get(paramState)
	if state == "" {
		return nil, &authorizationRequestError{
			redirectURI: redirectURI,
			state:       state,
			err:         model.AuthorizationRequestErrInvalidRequest,
			details: model.RequestErrorDetails{
				ParamName: paramState,
				Details:   "State required",
			},
		}
	}

	// REQUIRED
	responseTypeStr := query.Get(paramResponseType)
	if responseTypeStr == "" {
		return nil, &authorizationRequestError{
			redirectURI: redirectURI,
			state:       state,
			err:         model.AuthorizationRequestErrInvalidRequest,
			details: model.RequestErrorDetails{
				ParamName: paramResponseType,
				Details:   "Response type required",
			},
		}
	}
	responseType := model.AuthorizationResponseType(responseTypeStr)
	if !responseType.IsValid() {
		return nil, &authorizationRequestError{
			redirectURI, state,
			model.AuthorizationRequestErrUnsupportedResponseType,
			model.RequestErrorDetails{},
		}
	}

	// OPTIONAL
	scope := query.Get(paramScope)
	if scope == "" {
		// Use default scope
		scope = config.Current.OAuth.Scopes.Default
	} else {
		err = clientInfo.ValidateScopes(scope)
		if err != nil {
			return nil, &authorizationRequestError{
				redirectURI, state,
				model.AuthorizationRequestErrInvalidScope,
				model.RequestErrorDetails{},
			}
		}
	}

	// REQUIRED
	codeChallenge := query.Get(paramCodeChallenge)
	if codeChallenge == "" {
		return nil, &authorizationRequestError{
			redirectURI, state,
			model.AuthorizationRequestErrInvalidRequest,
			model.RequestErrorDetails{
				ParamName: paramCodeChallenge,
				Details:   "Code challenge required",
			},
		}
	}

	// REQUIRED
	codeChallengeMethodStr := query.Get(paramCodeChallengeMethod)
	if codeChallengeMethodStr == "" {
		return nil, &authorizationRequestError{
			redirectURI, state,
			model.AuthorizationRequestErrInvalidRequest,
			model.RequestErrorDetails{
				ParamName: paramCodeChallengeMethod,
				Details:   "Code challenge method required",
			},
		}
	}
	codeChallengeMethod := model.CodeChallengeMethod(codeChallengeMethodStr)
	if !codeChallengeMethod.IsValid() {
		return nil, &authorizationRequestError{
			redirectURI, state,
			model.AuthorizationRequestErrInvalidRequest,
			model.RequestErrorDetails{
				ParamName: paramCodeChallengeMethod,
				Details:   "Transform algorithm is not supported",
			},
		}
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

	return authRequest, nil
}
