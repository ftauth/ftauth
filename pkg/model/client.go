package model

import (
	_ "embed" // For GraphQL embeds
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ftauth/ftauth/pkg/graphql"
	"github.com/ftauth/ftauth/pkg/util"
	"github.com/ftauth/ftauth/pkg/util/sqlutil"
	"github.com/gofrs/uuid"
)

// GraphQL embeds
var (
	//go:embed gql/fragments/AllClientInfo.graphql
	AllClientInfo string
)

// ClientType identifies the level of confidentiality the
// client can maintain. For applications that can keep a
// secret, ClientTypeConfidential is used. For those that
// can't, like web browser-based apps, ClientTypePublic
// is used instead.
//
// See RFC 6749 2.1
type ClientType string

const (
	// ClientTypeConfidential identifies a client that can
	// keep its credentials confidential.
	//
	// Examples typically include servers which have restricted
	// access to the client credentials, or web apps which
	// maintain their secrets on a secure server.
	ClientTypeConfidential ClientType = "confidential"

	// ClientTypePublic identifies a client that cannot
	// keep its credentials confidential.
	//
	// Examples typically include SPAs and native apps
	// which cannot store secure information.
	ClientTypePublic ClientType = "public"
)

// GQL returns the GraphQL representation.
func (typ ClientType) GQL() string {
	return string(typ)
}

// ClientInfo holds all relevant information about a client.
type ClientInfo struct {
	ID               string      `json:"id"` // A UUID v4 string which uniquely idenitifes a particular client.
	Name             string      `json:"name"`
	Type             ClientType  `json:"type"`
	Secret           string      `json:"secret,omitempty"`
	SecretExpiry     *time.Time  `json:"secret_expires_at,omitempty"` // Required if client_secret is issued. Time at which secret expires or 0 for no expiry.
	RedirectURIs     []string    `json:"redirect_uris"`
	Scopes           []*Scope    `json:"scopes"`
	JWKsURI          string      `json:"jwks_uri,omitempty"`
	LogoURI          string      `json:"logo_uri,omitempty"`
	GrantTypes       []GrantType `json:"grant_types"`
	AccessTokenLife  int         `json:"access_token_life"`  // Lifetime of access token, in seconds
	RefreshTokenLife int         `json:"refresh_token_life"` // Lifetime of refresh token, in seconds
	Providers        []Provider  `json:"providers"`
}

// NewClient creates a new client with the provided values. This
// is the preferred method for creating a client, since it will
// populate some required values for you.
func NewClient(
	name string,
	typ ClientType,
	redirectUris []string,
	scopes []*Scope,
	jwksURI,
	logoURI string,
	accessTokenLife,
	refreshTokenLife int,
	providers []Provider,
) (*ClientInfo, error) {
	var secret string
	if typ == ClientTypeConfidential {
		secret = GenerateAuthorizationCode()
	}
	var grantTypes []GrantType
	if typ == ClientTypeConfidential {
		grantTypes = []GrantType{GrantTypeClientCredentials}
	} else if typ == ClientTypePublic {
		grantTypes = []GrantType{GrantTypeAuthorizationCode, GrantTypeRefreshToken}
	}
	id, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	return &ClientInfo{
		ID:               id.String(),
		Name:             name,
		Type:             typ,
		Secret:           secret,
		RedirectURIs:     redirectUris,
		Scopes:           scopes,
		JWKsURI:          jwksURI,
		LogoURI:          logoURI,
		GrantTypes:       grantTypes,
		AccessTokenLife:  accessTokenLife,
		RefreshTokenLife: refreshTokenLife,
		Providers:        providers,
	}, nil
}

// Update creates a new copy of client and updates fields from clientUpdate.
// If clientUpdate is empty, no new copy is created, and the original instance
// is returned.
func (client *ClientInfo) Update(clientUpdate ClientInfoUpdate) *ClientInfo {
	var changedValues bool
	updatedClient := *client
	if clientUpdate.Name != nil {
		changedValues = true
		updatedClient.Name = *clientUpdate.Name
	}
	if clientUpdate.RedirectURIs != nil {
		changedValues = true
		updatedClient.RedirectURIs = *clientUpdate.RedirectURIs
	}
	if clientUpdate.Scopes != nil {
		changedValues = true
		updatedClient.Scopes = *clientUpdate.Scopes
	}
	if clientUpdate.JWKsURI != nil {
		changedValues = true
		updatedClient.JWKsURI = *clientUpdate.JWKsURI
	}
	if clientUpdate.LogoURI != nil {
		changedValues = true
		updatedClient.LogoURI = *clientUpdate.LogoURI
	}
	if clientUpdate.AccessTokenLife != nil {
		changedValues = true
		updatedClient.AccessTokenLife = *clientUpdate.AccessTokenLife
	}
	if clientUpdate.RefreshTokenLife != nil {
		changedValues = true
		updatedClient.RefreshTokenLife = *clientUpdate.RefreshTokenLife
	}
	if clientUpdate.Providers != nil {
		changedValues = true
		updatedClient.Providers = *clientUpdate.Providers
	}
	if changedValues {
		return &updatedClient
	}
	return client
}

// GQL returns the GraphQL representation.
func (client *ClientInfo) GQL() string {
	gql := `{id: "%s"
name: "%s"
type: %s
secret: "%s"
%s
redirect_uris: %s
jwks_uri: "%s"
logo_uri: "%s"
scopes: %s
grant_types: %s
access_token_life: %d
refresh_token_life: %d
providers: %s}`

	var secretExpiry string
	if client.SecretExpiry != nil {
		secretExpiry = fmt.Sprintf(`secret_expiry: "%s"`, client.SecretExpiry.Format(time.RFC3339))
	}

	return fmt.Sprintf(
		gql,
		client.ID,
		client.Name,
		client.Type,
		client.Secret,
		secretExpiry,
		graphql.BuildGraphQLArray(client.RedirectURIs),
		client.JWKsURI,
		client.LogoURI,
		graphql.MarshalGQL(client.Scopes),
		graphql.MarshalGQL(client.GrantTypes),
		client.AccessTokenLife,
		client.RefreshTokenLife,
		graphql.MarshalGQL(client.Providers),
	)
}

// IsDevClient returns true if the client permits localhost redirect URIs.
func (client *ClientInfo) IsDevClient() bool {
	for _, uri := range client.RedirectURIs {
		if uri == LocalhostRedirectURI {
			return true
		}
	}
	return false
}

// IsValid checks whether the client info has required and valid parameters,
// returning an error if not.
func (client *ClientInfo) IsValid() error {
	if client.ID == "" {
		return util.ErrMissingParameter("id")
	}
	if client.Name == "" {
		return util.ErrMissingParameter("name")
	}
	if client.Type == "" {
		return util.ErrMissingParameter("type")
	}
	if client.Type == ClientTypeConfidential {
		if client.Secret == "" {
			return util.ErrMissingParameter("secret")
		}
	} else {
		if len(client.RedirectURIs) == 0 {
			return util.ErrMissingParameter("redirect_uris")
		}
		for _, uri := range client.RedirectURIs {
			if uri == "localhost" {
				continue
			}
			redirectURI, err := url.Parse(uri)
			if err != nil {
				return fmt.Errorf("Invalid redirect URI: %s: %v", uri, err)
			}
			if redirectURI.Hostname() == "localhost" {
				continue
			}
			if redirectURI.Scheme == "http" {
				return fmt.Errorf("invalid redirect URI: %s: HTTP is not allowed", uri)
			}
			if redirectURI.Hostname() == "" {
				return fmt.Errorf("invalid redirect URI: %s: Missing host", uri)
			}
		}
	}
	if len(client.Scopes) == 0 {
		return util.ErrMissingParameter("scopes")
	}
	if len(client.GrantTypes) == 0 {
		return util.ErrMissingParameter("grant_types")
	}
	if client.AccessTokenLife <= 0 {
		return util.ErrInvalidParameter("access_token")
	}
	if client.RefreshTokenLife <= 0 {
		return util.ErrInvalidParameter("refresh_token")
	}
	if len(client.Providers) == 0 {
		return util.ErrInvalidParameter("providers")
	}

	return nil
}

// ClientInfoUpdate holds updateable parameters for ClientInfo.
type ClientInfoUpdate struct {
	ID               string      `json:"id"`
	Name             *string     `json:"client_name,omitempty"`
	RedirectURIs     *[]string   `json:"redirect_uris,omitempty"`
	Scopes           *[]*Scope   `json:"scopes,omitempty"`
	JWKsURI          *string     `json:"jwks_uri,omitempty"`
	LogoURI          *string     `json:"logo_uri,omitempty"`
	AccessTokenLife  *int        `json:"access_token_life,omitempty"`
	RefreshTokenLife *int        `json:"refresh_token_life,omitempty"`
	Providers        *[]Provider `json:"providers,omitempty"`
}

func parseGrantTypes(grants string) []GrantType {
	var grantTypes []GrantType
	for _, str := range sqlutil.ParseArray(grants) {
		grantType := GrantType(str)
		if grantType.IsValid() {
			grantTypes = append(grantTypes, grantType)
		}
	}
	return grantTypes
}

// GQL returns the GraphQL representation.
func (clientUpdate *ClientInfoUpdate) GQL() string {
	bldr := strings.Builder{}
	if clientUpdate.Name != nil {
		bldr.WriteString(fmt.Sprintf(`name: "%s"`, *clientUpdate.Name))
		bldr.WriteByte('\n')
	}
	if clientUpdate.RedirectURIs != nil {
		bldr.WriteString("redirect_uris: " + graphql.BuildGraphQLArray(*clientUpdate.RedirectURIs))
		bldr.WriteByte('\n')
	}
	if clientUpdate.Scopes != nil {
		bldr.WriteString("scopes: " + graphql.MarshalGQL(*clientUpdate.Scopes))
		bldr.WriteByte('\n')
	}
	if clientUpdate.JWKsURI != nil {
		bldr.WriteString(fmt.Sprintf(`jwks_uri: "%s"`, *clientUpdate.JWKsURI))
		bldr.WriteByte('\n')
	}
	if clientUpdate.LogoURI != nil {
		bldr.WriteString(fmt.Sprintf(`logo_uri: "%s"`, *clientUpdate.LogoURI))
		bldr.WriteByte('\n')
	}
	if clientUpdate.AccessTokenLife != nil {
		bldr.WriteString(fmt.Sprintf("access_token_life: %d", *clientUpdate.AccessTokenLife))
		bldr.WriteByte('\n')
	}
	if clientUpdate.RefreshTokenLife != nil {
		bldr.WriteString(fmt.Sprintf("refresh_token_life: %d", *clientUpdate.RefreshTokenLife))
		bldr.WriteByte('\n')
	}
	if clientUpdate.Providers != nil {
		bldr.WriteString("providers: " + graphql.MarshalGQL(*clientUpdate.Providers))
		bldr.WriteByte('\n')
	}

	return "{" + bldr.String() + "}"
}

// Scope identifies an access scope for a client
type Scope struct {
	Name    string        `db:"name" json:"name"`                 // Primary key
	Ruleset string        `db:"ruleset" json:"ruleset,omitempty"` // Set of rules - in JSON format
	Clients []*ClientInfo `json:"clients,omitempty"`
	Users   []*User       `json:"users,omitempty"`
}

// GQL returns the GraphQL representation.
func (scope *Scope) GQL() string {
	return fmt.Sprintf(
		`{name:"%s"}`,
		scope.Name,
	)
}

// ValidateScopes affirms whether the client supports the given scopes.
func (client *ClientInfo) ValidateScopes(scopes string) error {
	// Parse scope
	scopeTokens, err := ParseScope(scopes)
	if err != nil {
		return err
	}
	if len(scopeTokens) == 0 {
		return ErrEmptyScope
	}
	// Validate scope tokens
	for _, scopeToken := range scopeTokens {
		valid := false
		for _, scope := range client.Scopes {
			if scopeToken == scope.Name {
				valid = true
				break
			}
		}
		if !valid {
			return errors.New("invalid scope")
		}
	}

	return nil
}

// ClientRegistrationError is an error that occurred during the client
// registration process.
type ClientRegistrationError string

// Valid client registration errors as defined by RFC 7591.
const (
	ClientRegistrationErrorInvalidRedirectURI          ClientRegistrationError = "invalid_redirect_uri"
	ClientRegistrationErrorInvalidClientMetadata       ClientRegistrationError = "invalid_client_metadata"
	ClientRegistrationErrorInvalidSoftwareStatement    ClientRegistrationError = "invalid_software_statement"
	ClientRegistrationErrorUnapprovedSoftwareStatement ClientRegistrationError = "unapproved_software_statement"
)

// Description returns details about the error that occurred.
func (err ClientRegistrationError) Description(invalidParameter string) string {
	switch err {
	case ClientRegistrationErrorInvalidRedirectURI:
		return "The value of one or more redirection URIs is invalid"
	case ClientRegistrationErrorInvalidClientMetadata:
		return "The value of one of the client metadata fields is invalid and the server has rejected the request.\n" +
			fmt.Sprintf("Invalid Paramater: %s", invalidParameter)
	case ClientRegistrationErrorInvalidSoftwareStatement:
		return "The software statement presented is invalid."
	case ClientRegistrationErrorUnapprovedSoftwareStatement:
		return "The software statement presented is not approved for use by this authorization server."
	}

	return "An unknown error occurred."
}

// ClientOption is a bitmask for different client flags.
type ClientOption byte

// Flags for clients
const (
	ClientOptionNone  ClientOption = 0
	ClientOptionAdmin ClientOption = (1 << iota) // the admin client
)

// IsValidRedirectURI returns true if the given URI is a localhost URI or
// matches one of the registered URIs.
func (client *ClientInfo) IsValidRedirectURI(uri string) bool {
	redirectURI, err := url.Parse(uri)
	if err != nil {
		return false
	}
	if client.IsDevClient() && redirectURI.Hostname() == LocalhostRedirectURI {
		return true
	}
	for _, clientRedirect := range client.RedirectURIs {
		if uri == clientRedirect {
			return true
		}
	}
	return false
}
