package model

import (
	"errors"
	"fmt"
	"time"

	"github.com/ftauth/ftauth/util/sqlutil"
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

// ClientInfo holds all relevant information about a client.
type ClientInfo struct {
	ID               string      `json:"client_id"` // A UUID v4 string which uniquely idenitifes a particular client.
	Name             string      `json:"client_name"`
	Type             ClientType  `json:"client_type"`
	Secret           string      `json:"client_secret"`
	SecretExpiry     time.Time   `json:"client_secret_expires_at"` // Required if client_secret is issued. Time at which secret expires or 0 for no expiry.
	RedirectURIs     []string    `json:"redirect_uris"`
	Scopes           []*Scope    `json:"scopes"`
	JWKsURI          string      `json:"jwks_uri"`
	LogoURI          string      `json:"logo_uri"`
	GrantTypes       []GrantType `json:"grant_types"`
	AccessTokenLife  int         `json:"access_token_life"`  // Lifetime of access token, in seconds
	RefreshTokenLife int         `json:"refresh_token_life"` // Lifetime of refresh token, in seconds
}

// ClientInfoEntity holds client info for transfer on the wire,
// e.g. when communicating with a DB.
type ClientInfoEntity struct {
	ID               string     `db:"id"`
	Name             string     `db:"name"`
	Type             ClientType `db:"type"`
	Secret           string     `db:"secret"`
	SecretExpiry     time.Time  `db:"secret_expiry"`
	RedirectURIs     string     `db:"redirect_uris"`
	Scopes           string     `db:"scopes"`
	JWKsURI          string     `db:"jwks_uri"`
	LogoURI          string     `db:"logo_uri"`
	GrantTypes       string     `db:"grant_types"`
	AccessTokenLife  int        `db:"access_token_life"`
	RefreshTokenLife int        `db:"refresh_token_life"`
}

// ToEntity converts the model type to the entity type.
func (clientInfo *ClientInfo) ToEntity() *ClientInfoEntity {
	var scopes []string
	for _, scope := range clientInfo.Scopes {
		scopes = append(scopes, scope.Name)
	}
	var grants []string
	for _, grant := range clientInfo.GrantTypes {
		grants = append(grants, string(grant))
	}
	return &ClientInfoEntity{
		ID:               clientInfo.ID,
		Name:             clientInfo.Name,
		Type:             clientInfo.Type,
		Secret:           clientInfo.Secret,
		SecretExpiry:     clientInfo.SecretExpiry,
		RedirectURIs:     sqlutil.GenerateArrayString(clientInfo.RedirectURIs),
		Scopes:           sqlutil.GenerateArrayString(scopes),
		JWKsURI:          clientInfo.JWKsURI,
		LogoURI:          clientInfo.LogoURI,
		GrantTypes:       sqlutil.GenerateArrayString(grants),
		AccessTokenLife:  clientInfo.AccessTokenLife,
		RefreshTokenLife: clientInfo.RefreshTokenLife,
	}
}

// ToModel converts the entity type to the model type.
func (entity *ClientInfoEntity) ToModel(scopes []*Scope) *ClientInfo {
	return &ClientInfo{
		ID:               entity.ID,
		Name:             entity.Name,
		Type:             entity.Type,
		Secret:           entity.Secret,
		RedirectURIs:     sqlutil.ParseArray(entity.RedirectURIs),
		Scopes:           scopes,
		JWKsURI:          entity.JWKsURI,
		LogoURI:          entity.LogoURI,
		GrantTypes:       parseGrantTypes(entity.GrantTypes),
		AccessTokenLife:  entity.AccessTokenLife,
		RefreshTokenLife: entity.RefreshTokenLife,
	}
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

// Scope identifies an access scope for a client
type Scope struct {
	Name    string `db:"name" json:"name"`       // Primary key
	Ruleset string `db:"ruleset" json:"ruleset"` // Set of rules - in JSON format
}

// ValidateScopes affirms whether the client supports the given scopes.
func (clientInfo *ClientInfo) ValidateScopes(scopes string) error {
	// Parse scope
	scopeTokens, err := ParseScope(scopes)
	if err != nil {
		return err
	}
	// Validate scope tokens
	for _, scopeToken := range scopeTokens {
		valid := false
		for _, scope := range clientInfo.Scopes {
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

// ClientOption is a bitmask for different client flagss.
type ClientOption byte

// Flags for clients
const (
	ClientOptionNone  ClientOption = 0
	ClientOptionAdmin ClientOption = (1 << iota) // the admin client
)
