package model

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
)

var (
	// ErrInvalidRedirectURI identifies an invalid or missing redirect URI
	// per [RFC 6749 3.1.2.4](https://tools.ietf.org/html/rfc6749#section-3.1.2.4)
	ErrInvalidRedirectURI = errors.New("invalid redirect uri")
)

// AuthorizationRequest holds the request sent to the authorization endpoint.
type AuthorizationRequest struct {
	ID                  string              `db:"id"` // The session ID
	GrantType           string              `db:"grant_type"`
	ClientID            string              `db:"client_id"`
	Scope               string              `db:"scope"`
	State               string              `db:"state"`
	RedirectURI         string              `db:"redirect_uri"`
	Code                string              `db:"code"`
	Expiry              int64               `db:"exp"`
	CodeChallenge       string              `db:"code_challenge"`
	CodeChallengeMethod CodeChallengeMethod `db:"code_challenge_method"`
	UserID              string              `db:"user"`
}

// TokenRequest holds information for the request of an access token.
// This request is made through the /token endpoint using an authorization
// code provided by the /authorize endpoint.
type TokenRequest struct {
	GrantType    GrantType `json:"grant_type"`
	Code         string    `json:"code"`
	RedirectURI  string    `json:"redirect_uri"`
	ClientID     string    `json:"client_id"`
	CodeVerifier string    `json:"code_verifier"`
	Scope        string    `json:"scope"`
}

// RequestError provides an interface that errors should conform to
// to ensure that all information is available for the enumerations.
type RequestError interface {
	IsValid() bool
	Description(details RequestErrorDetails) string
	URI() string
}

// RequestErrorDetails holds detailed information about why the request
// failed. This provides additional debugging information for client
// developers but is not required per OAuth specs.
type RequestErrorDetails struct {
	ParamName string
	Details   string
}

// AuthorizationRequestError represents an error during an authorization request.
type AuthorizationRequestError string

var (
	// ValidRequestErrorFieldRegex represents the range of characters allowed in
	// a field of a request error redirect query parameter per
	// [RFC 6749 4.2.2.1](https://tools.ietf.org/html/rfc6749#section-4.2.2.1)
	ValidRequestErrorFieldRegex = regexp.MustCompile(`^[\x21\x23-\x5B\x5D-\x7E]+$`)
)

const (
	// AuthorizationRequestErrInvalidRequest means the request is missing a required parameter, includes an
	// invalid parameter value, includes a parameter more than once, or is otherwise malformed.
	AuthorizationRequestErrInvalidRequest AuthorizationRequestError = "invalid_request"

	// AuthorizationRequestErrUnauthorizedClient means the client is not authorized to request an access token
	// using this method.
	AuthorizationRequestErrUnauthorizedClient AuthorizationRequestError = "unauthorized_client"

	// AuthorizationRequestErrAccessDenied means the resource owner or authorization server denied the request.
	AuthorizationRequestErrAccessDenied AuthorizationRequestError = "access_denied"

	// AuthorizationRequestErrUnsupportedResponseType means the authorization server does not support
	// obtaining an access token using this method.
	AuthorizationRequestErrUnsupportedResponseType AuthorizationRequestError = "unsupported_response_type"

	// AuthorizationRequestErrInvalidScope means the requested scope is invalid, unknown, or malformed.
	AuthorizationRequestErrInvalidScope AuthorizationRequestError = "invalid_scope"

	// AuthorizationRequestErrServerError The authorization server encountered an unexpected
	// condition that prevented it from fulfilling the request.
	// (This error code is needed because a 500 Internal Server Error HTTP status code
	// cannot be returned to the client via an HTTP redirect.)
	AuthorizationRequestErrServerError AuthorizationRequestError = "server_error"

	// AuthorizationRequestErrTemporarilyUnavailable means the authorization server is currently unable
	// to handle the request due to a temporary overloading or maintenance of the server.
	// (This error code is needed because a 503 Service Unavailable HTTP status code cannot
	// be returned to the client via an HTTP redirect.)
	AuthorizationRequestErrTemporarilyUnavailable AuthorizationRequestError = "temporarily_unavailable"
)

// IsValid returns true if this error code is valid.
func (err AuthorizationRequestError) IsValid() bool {
	switch err {
	case AuthorizationRequestErrInvalidRequest,
		AuthorizationRequestErrUnauthorizedClient,
		AuthorizationRequestErrAccessDenied,
		AuthorizationRequestErrUnsupportedResponseType,
		AuthorizationRequestErrInvalidScope,
		AuthorizationRequestErrServerError,
		AuthorizationRequestErrTemporarilyUnavailable:
		return true
	}

	return false
}

// Description returns the optional "error_description" string which assists client
// developers in debugging error codes by providing additional information.
func (err AuthorizationRequestError) Description(details RequestErrorDetails) string {
	switch err {
	case AuthorizationRequestErrInvalidRequest:
		return fmt.Sprintf(`The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.
Invalid: %s
Details: %s`, details.ParamName, details.Details)
	case AuthorizationRequestErrUnauthorizedClient:
		return "The client is not authorized to request an access token using this method."
	case AuthorizationRequestErrAccessDenied:
		return "The resource owner or authorization server denied the request."
	case AuthorizationRequestErrUnsupportedResponseType:
		return "The authorization server does not support obtaining an access token using this method."
	case AuthorizationRequestErrInvalidScope:
		return "The requested scope is invalid, unknown, or malformed."
	case AuthorizationRequestErrServerError:
		// Same as HTTP 500
		return http.StatusText(http.StatusInternalServerError)
	case AuthorizationRequestErrTemporarilyUnavailable:
		// Same as HTTP 503
		return http.StatusText(http.StatusServiceUnavailable)
	}

	return "An unknown error occurred."
}

// URI returns the optional "error_uri" parameter string which provides a URL where
// client developers can go to get more information about a particular error.
func (err AuthorizationRequestError) URI() string {
	return "https://tools.ietf.org/html/rfc6749#section-4.2.2.1"
}

// TokenRequestError represents an error during the token request.
type TokenRequestError string

const (
	// TokenRequestErrInvalidRequest means he request is missing a required parameter,
	// includes an unsupported parameter value (other than grant type),  repeats a parameter,
	// includes multiple credentials, utilizes more than one mechanism for authenticating the
	// client, or is otherwise malformed.
	TokenRequestErrInvalidRequest TokenRequestError = "invalid_request"

	// TokenRequestErrInvalidClient means client authentication failed (e.g., unknown client, no
	// client authentication included, or unsupported authentication method).
	TokenRequestErrInvalidClient TokenRequestError = "invalid_client"

	// TokenRequestErrInvalidGrant means the provided authorization grant (e.g. authorization
	// code) or refresh token is invalid, expired, revoked, does not match the redirection
	// URI used in the authorization request, or was issued to another client.
	TokenRequestErrInvalidGrant TokenRequestError = "invalid_grant"

	// TokenRequestErrUnauthorizedClient means the authenticated client is not authorized to use
	// this authorization grant type.
	TokenRequestErrUnauthorizedClient TokenRequestError = "unauthorized_client"

	// TokenRequestErrUnsupportedGrantType means the authorization grant type is not supported
	// by the authorization server.
	TokenRequestErrUnsupportedGrantType TokenRequestError = "unsupported_grant_type"

	// TokenRequestErrInvalidScope means the requested scope is invalid, unknown, malformed,
	// or exceeds the scope granted by the resource owner.
	TokenRequestErrInvalidScope TokenRequestError = "invalid_scope"

	// TokenRequestErrInvalidDPoP means the client has provided an invalid DPoP proof
	TokenRequestErrInvalidDPoP TokenRequestError = "invalid_dpop_proof"
)

// IsValid returns true if this error code is valid.
func (err TokenRequestError) IsValid() bool {
	switch err {
	case TokenRequestErrInvalidRequest,
		TokenRequestErrInvalidClient,
		TokenRequestErrInvalidGrant,
		TokenRequestErrUnauthorizedClient,
		TokenRequestErrUnsupportedGrantType,
		TokenRequestErrInvalidScope,
		TokenRequestErrInvalidDPoP:
		return true
	}

	return false
}

// Description returns the optional "error_description" string which assists client
// developers in debugging error codes by providing additional information.
func (err TokenRequestError) Description(details RequestErrorDetails) string {
	switch err {
	case TokenRequestErrInvalidRequest:
		return fmt.Sprintf(
			`The request is missing a required parameter, includes an unsupported parameter value (other than grant type), repeats a parameter, includes multiple credentials, utilizes more than one mechanism for authenticating the client, or is otherwise malformed.
			   Invalid: %s
			   Details: %s`, details.ParamName, details.Details)
	case TokenRequestErrInvalidClient:
		return fmt.Sprintf(
			`Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).
				Reason: %s`, details.Details)
	case TokenRequestErrInvalidGrant:
		return `The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.`
	case TokenRequestErrUnauthorizedClient:
		return "The authenticated client is not authorized to use this authorization grant type."
	case TokenRequestErrUnsupportedGrantType:
		return "The authorization grant type is not supported by the authorization server."
	case TokenRequestErrInvalidScope:
		return `The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the resource owner.`
	case TokenRequestErrInvalidDPoP:
		return `The provided DPoP proof failed validation: ` + details.Details
	}

	return "An unknown error occurred"
}

// URI returns the optional "error_uri" parameter string which provides a URL where
// client developers can go to get more information about a particular error.
func (err TokenRequestError) URI() string {
	return "https://tools.ietf.org/html/rfc6749#section-5.2"
}

// StatusCode returns the HTTP status code which should be returned for this error.
// The OAuth protocol allows for only 400 & 401 status codes for error responses.
func (err TokenRequestError) StatusCode() int {
	switch err {
	case TokenRequestErrInvalidClient, TokenRequestErrInvalidGrant:
		return http.StatusUnauthorized
	}
	return http.StatusBadRequest
}
