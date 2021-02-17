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

	// GrantTypeResourceOwnerPasswordCredentials uses a username/password combo to obtain an
	// access token. While this was removed from OAuth 2.1 due to its inherent lack of security,
	// for developers who control both the client and resource server, this provides a more
	// convenient and customizable means of authenticating users without many of the risks.
	GrantTypeResourceOwnerPasswordCredentials GrantType = "password"
)

// IsValid returns whether or not this grant type is supported.
func (typ GrantType) IsValid() bool {
	switch typ {
	case GrantTypeAuthorizationCode, GrantTypeClientCredentials, GrantTypeRefreshToken, GrantTypeResourceOwnerPasswordCredentials:
		return true
	}
	return false
}
