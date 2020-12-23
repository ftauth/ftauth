package model

import (
	"fmt"
	"time"

	"github.com/dnys1/ftoauth/util/sqlutil"
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

// Identifier is a 36-character UUID v4 string which uniquely
// idenitifes a particular client.
//
// See RFC 6749 2.2
type Identifier string

// RedirectRegistrationType defines the method by which redirect
// comparison occurs: by prefix or by full string comparison.
//
// Example:
// 	Client registers http://example.com:8080/redirect
// 	With *prefix* matching
// 		- redirect_uri=http://example.com/redirect would be valid
//		- redirect_uri=http://example.com/redirect?param=value would be valid
//		- redirect_uri=http://example.com/other would be invalid
// 	With *full* matching
// 		* redirect_uri=http://example.com/redirect would be valid
//		* redirect_uri=http://example.com/redirect?param=value would be invalid
//		* redirect_uri=http://example.com/other would be ininvalid
type RedirectRegistrationType int

const (
	// RedirectRegistrationTypeFull matches redirect URIs sent in
	// authorization requests by exact string matching.
	RedirectRegistrationTypeFull RedirectRegistrationType = iota

	// RedirectRegistrationTypePrefix matches redirect URIs sent in
	// authorization requests by prefix alone.
	// This is omitted from the OAuth 2.1 spec and thus deprecated
	// by FTOAuth.
	RedirectRegistrationTypePrefix
)

// IsValid returns whether the registration type is supported.
func (typ RedirectRegistrationType) IsValid() bool {
	switch typ {
	case RedirectRegistrationTypeFull:
		return true
	}
	return false
}

// ClientInfo holds all relevant information about a client.
type ClientInfo struct {
	ID           Identifier  `json:"client_id"`
	Name         string      `json:"client_name"`
	Type         ClientType  `json:"client_type"`
	Secret       string      `json:"client_secret"`
	SecretExpiry time.Time   `json:"client_secret_expires_at"` // Required if client_secret is issued. Time at which secret expires or 0 for no expiry.
	RedirectURIs []string    `json:"redirect_uris"`
	Scopes       []*Scope    `json:"scopes"`
	JWKsURI      string      `json:"jwks_uri"`
	LogoURI      string      `json:"logo_uri"`
	GrantTypes   []GrantType `json:"grant_types"`
}

// ClientInfoEntity holds client info for transfer on the wire,
// e.g. when communicating with a DB.
type ClientInfoEntity struct {
	ID           Identifier `db:"id"`
	Type         ClientType `db:"type"`
	Secret       string     `db:"secret"`
	SecretExpiry time.Time  `db:"secret_expiry"`
	RedirectURIs string     `db:"redirect_uris"`
	Scopes       string     `db:"scopes"`
	JWKsURI      string     `db:"jwks_uri"`
	LogoURI      string     `db:"logo_uri"`
	GrantTypes   string     `db:"grant_types"`
}

// ToModel converts the entity type to the model type.
func (entity *ClientInfoEntity) ToModel(scopes []*Scope) *ClientInfo {
	return &ClientInfo{
		ID:           entity.ID,
		Type:         entity.Type,
		Secret:       entity.Secret,
		RedirectURIs: sqlutil.ParseArray(entity.RedirectURIs),
		Scopes:       scopes,
		JWKsURI:      entity.JWKsURI,
		LogoURI:      entity.LogoURI,
		GrantTypes:   parseGrantTypes(entity.GrantTypes),
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
	Name    string `db:"name"`    // Primary key
	Ruleset string `db:"ruleset"` // Set of rules - in JSON format
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
