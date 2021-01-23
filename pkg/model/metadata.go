package model

import (
	"database/sql"

	"github.com/ftauth/ftauth/pkg/util/sqlutil"
)

// AuthorizationServerMetadataPostgresEntity holds AuthorizationServerMetadata info for
// transfer on the wire, e.g. communicating with a Postgres DB
type AuthorizationServerMetadataPostgresEntity struct {
	Issuer                 string         `db:"issuer"`                   // Required, the auth server's issuer identifier
	AuthorizationEndpoint  string         `db:"authorization_endpoint"`   // Required, URL of the auth server's authorization endpoint
	TokenEndpoint          string         `db:"token_endpoint"`           // Required, URL of the auth server's token endpoint
	JwksURI                sql.NullString `db:"jwks_uri"`                 // Optional, URL of the auth server's JWK Set document
	RegistrationEndpoint   sql.NullString `db:"registration_endpoint"`    // Optional, URL of dynamic client registration endpoint
	ScopesSupported        string         `db:"scopes"`                   // Recommended, JSON array containing valid "scope"
	ResponseTypesSupported string         `db:"response_types_supported"` // Required, JSON array containing "response_type" values
}

// AuthorizationServerMetadataOracleEntity holds AuthorizationServerMetadata info for
// transfer on the wire, e.g. communicating with an Oracle DB
type AuthorizationServerMetadataOracleEntity struct {
	Issuer                 string         `db:"issuer"`                   // Required, the auth server's issuer identifier
	AuthorizationEndpoint  string         `db:"authorization_endpoint"`   // Required, URL of the auth server's authorization endpoint
	TokenEndpoint          string         `db:"token_endpoint"`           // Required, URL of the auth server's token endpoint
	JwksURI                sql.NullString `db:"jwks_uri"`                 // Optional, URL of the auth server's JWK Set document
	RegistrationEndpoint   sql.NullString `db:"registration_endpoint"`    // Optional, URL of dynamic client registration endpoint
	ScopesSupported        string         `db:"scopes"`                   // Recommended, JSON array containing valid "scope"
	ResponseTypesSupported string         `db:"response_types_supported"` // Required, JSON array containing "response_type" values
}

// AuthorizationServerMetadata holds metadata related to this authorization server
// which is returned to clients requesting information via RFC 8414: https://tools.ietf.org/html/rfc8414
type AuthorizationServerMetadata struct {
	Issuer                 string                      `json:"issuer"`                          // Required, the auth server's issuer identifier
	AuthorizationEndpoint  string                      `json:"authorization_endpoint"`          // Required, URL of the auth server's authorization endpoint
	TokenEndpoint          string                      `json:"token_endpoint"`                  // Required, URL of the auth server's token endpoint
	JwksURI                string                      `json:"jwks_uri,omitempty"`              // Optional, URL of the auth server's JWK Set document
	RegistrationEndpoint   string                      `json:"registration_endpoint,omitempty"` // Optional, URL of dynamic client registration endpoint
	ScopesSupported        []string                    `json:"scopes"`                          // Recommended, JSON array containing valid "scope"
	ResponseTypesSupported []AuthorizationResponseType `json:"response_types_supported"`        // Required, JSON array containing "response_type" values
}

// NewAuthorizationServerMetadata creates a metadata object from an entity.
func (entity *AuthorizationServerMetadataPostgresEntity) NewAuthorizationServerMetadata() *AuthorizationServerMetadata {
	responseTypes := sqlutil.ParseArray(entity.ResponseTypesSupported)
	return &AuthorizationServerMetadata{
		Issuer:                 entity.Issuer,
		AuthorizationEndpoint:  entity.AuthorizationEndpoint,
		TokenEndpoint:          entity.TokenEndpoint,
		JwksURI:                entity.JwksURI.String,
		RegistrationEndpoint:   entity.RegistrationEndpoint.String,
		ScopesSupported:        sqlutil.ParseArray(entity.ScopesSupported),
		ResponseTypesSupported: parseAuthorizationResponseTypes(responseTypes),
	}
}

// NewAuthorizationServerMetadata creates a metadata object from an entity.
func (entity *AuthorizationServerMetadataOracleEntity) NewAuthorizationServerMetadata() *AuthorizationServerMetadata {
	responseTypes := sqlutil.ParseArray(entity.ResponseTypesSupported)
	return &AuthorizationServerMetadata{
		Issuer:                 entity.Issuer,
		AuthorizationEndpoint:  entity.AuthorizationEndpoint,
		TokenEndpoint:          entity.TokenEndpoint,
		JwksURI:                entity.JwksURI.String,
		RegistrationEndpoint:   entity.RegistrationEndpoint.String,
		ScopesSupported:        sqlutil.ParseArray(entity.ScopesSupported),
		ResponseTypesSupported: parseAuthorizationResponseTypes(responseTypes),
	}
}

func parseAuthorizationResponseTypes(responseTypes []string) []AuthorizationResponseType {
	var authorizationResponseTypes []AuthorizationResponseType
	for _, typ := range responseTypes {
		authResponseType := AuthorizationResponseType(typ)
		if authResponseType.IsValid() {
			authorizationResponseTypes = append(authorizationResponseTypes, authResponseType)
		}
	}
	return authorizationResponseTypes
}
