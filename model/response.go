package model

// AuthorizationCodeLength TODO: Document code size
const AuthorizationCodeLength = 16

// AuthorizationCodeResponse contains the authorization response
// to the client in response to an authorization code request.
type AuthorizationCodeResponse struct {
	// The authorization code of length AuthorizationCodeLength
	Code string

	// The state sent by the client with the initial request.
	// This must be identical to the request state for the
	// response to be considered valid by the client.
	State string
}

// TokenResponse contains the access and refresh
// tokens generated through the implicit flow or token refresh.
type TokenResponse struct {
	// The access token
	AccessToken string `json:"access_token"`

	// The type of token (always JWT for FTOAuth)
	TokenType string `json:"token_type"`

	// The refresh token
	RefreshToken string `json:"refresh_token"`

	// The life of the token
	ExpiresIn int `json:"expires_in"`
}

// AuthorizationResponseType informs the server by which means to respond to an
// authorization request. RFC6749 supports two core types:
// 	* "code" for requesting an authorization code
// 	* "token" for requesting an access token (implicit grant)
type AuthorizationResponseType string

const (
	// AuthorizationResponseTypeCode is used with the authorization code flow.
	AuthorizationResponseTypeCode AuthorizationResponseType = "code"

	// AuthorizationResponseTypeToken is used with the implicit code flow.
	// As this has important security implications and is omitted in OAuth 2.1,
	// we have chosen to deprecate it in FTOAuth.
	AuthorizationResponseTypeToken AuthorizationResponseType = "token"
)

// IsValid returns true if this response type is supported.
func (typ AuthorizationResponseType) IsValid() bool {
	switch typ {
	case AuthorizationResponseTypeCode:
		return true
	}
	return false
}
