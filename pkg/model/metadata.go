package model

import (
	"github.com/ftauth/ftauth/pkg/jwt"
)

// AuthorizationServerMetadata holds metadata related to this authorization server
// which is returned to clients requesting information via RFC 8414: https://tools.ietf.org/html/rfc8414
type AuthorizationServerMetadata struct {
	Issuer                        string                      `json:"issuer"`                                           // Required, the auth server's issuer identifier
	AuthorizationEndpoint         string                      `json:"authorization_endpoint"`                           // Required, URL of the auth server's authorization endpoint
	TokenEndpoint                 string                      `json:"token_endpoint"`                                   // Required, URL of the auth server's token endpoint
	JwksURI                       string                      `json:"jwks_uri,omitempty"`                               // Optional, URL of the auth server's JWK Set document
	RegistrationEndpoint          string                      `json:"registration_endpoint,omitempty"`                  // Optional, URL of dynamic client registration endpoint
	ScopesSupported               []string                    `json:"scopes_supported"`                                 // Recommended, JSON array containing valid "scope"
	GrantTypesSupported           []GrantType                 `json:"grant_types_supported"`                            // JSON array containing a list of the OAuth 2.0 grant type values
	ResponseTypesSupported        []AuthorizationResponseType `json:"response_types_supported"`                         // Required, JSON array containing "response_type" values
	ResponseModesSupported        []string                    `json:"response_modes_supported"`                         // JSON array containing a list of the OAuth 2.0 "response_mode" values
	AuthMethodsSupported          []string                    `json:"token_endpoint_auth_methods_supported"`            // JSON array containing a list of client authentication methods supported
	AlgorithmsSupported           []jwt.Algorithm             `json:"token_endpoint_auth_signing_alg_values_supported"` // JSON array containing a list of the JWS signing algorithms
	CodeChallengeMethodsSupported []CodeChallengeMethod       `json:"code_challenge_methods_supported"`                 // JSON array of PKCE code challenge methods supported
}

type OIDCProviderMetadata struct {
	Issuer                           string                      `json:"issuer"`                                           // Required, the auth server's issuer identifier
	AuthorizationEndpoint            string                      `json:"authorization_endpoint"`                           // Required, URL of the auth server's authorization endpoint
	TokenEndpoint                    string                      `json:"token_endpoint"`                                   // Required, URL of the auth server's token endpoint
	UserInfoEndpoint                 string                      `json:"userinfo_endpoint"`                                // Recommended, URL of the OP's UserInfo Endpoint
	JwksURI                          string                      `json:"jwks_uri,omitempty"`                               // Required, URL of the auth server's JWK Set document
	RegistrationEndpoint             string                      `json:"registration_endpoint,omitempty"`                  // Recommended, URL of dynamic client registration endpoint
	ScopesSupported                  []string                    `json:"scopes_supported"`                                 // Recommended, JSON array containing valid "scope"
	GrantTypesSupported              []GrantType                 `json:"grant_types_supported"`                            // JSON array containing a list of the OAuth 2.0 grant type values
	ResponseTypesSupported           []AuthorizationResponseType `json:"response_types_supported"`                         // Required, JSON array containing "response_type" values
	ResponseModesSupported           []string                    `json:"response_modes_supported"`                         // JSON array containing a list of the OAuth 2.0 "response_mode" values
	AuthMethodsSupported             []string                    `json:"token_endpoint_auth_methods_supported"`            // JSON array containing a list of client authentication methods supported
	AlgorithmsSupported              []jwt.Algorithm             `json:"token_endpoint_auth_signing_alg_values_supported"` // JSON array containing a list of the JWS signing algorithms
	CodeChallengeMethodsSupported    []CodeChallengeMethod       `json:"code_challenge_methods_supported"`                 // JSON array of PKCE code challenge methods supported
	IdTokenSigningAlgValuesSupported []jwt.Algorithm             `json:"id_token_signing_alg_values_supported"`            // Required, JSON array containing a list of the JWS signing algorithms supported for the ID Token
	SubjectTypesSupported            []SubjectIdentifierType     `json:"subject_types_supported"`                          // Required, SON array containing a list of the Subject Identifier types
}

type SubjectIdentifierType string

const (
	SubjectIdentifierTypePublic   SubjectIdentifierType = "public"
	SubjectIdentifierTypePairwise SubjectIdentifierType = "pairwise"
)
