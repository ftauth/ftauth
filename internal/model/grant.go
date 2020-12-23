package model

// GrantType identifies the method by which token exchange
// will occur with the client.
type GrantType string

const (
	// GrantTypeAuthorizationCode represents the authorization code flow
	GrantTypeAuthorizationCode GrantType = "authorization_code"

	// GrantTypeClientCredentials represents the client credentials flow
	GrantTypeClientCredentials GrantType = "client_credentials"

	// GrantTypeRefreshToken uses a refresh token to retrieve an access token.
	GrantTypeRefreshToken GrantType = "refresh_token"
)

// IsValid returns whether or not this grant type is supported.
func (typ GrantType) IsValid() bool {
	switch typ {
	case GrantTypeAuthorizationCode, GrantTypeClientCredentials, GrantTypeRefreshToken:
		return true
	}
	return false
}
