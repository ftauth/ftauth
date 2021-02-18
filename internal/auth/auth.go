package auth

import (
	"encoding/base64"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

var (
	// ErrEmptyHeader represents an empty header.
	ErrEmptyHeader = errors.New("empty header")

	// ErrIncorrectHeaderFormat means the formatting of the header was incorrect.
	ErrIncorrectHeaderFormat = errors.New("incorrect header format")

	// ErrInvalidToken means an invalid character was present in the auth token.
	// Only base64 digits are allowed.
	ErrInvalidToken = errors.New("invalid token")

	// ErrMissingParameter means that a required parameter is missing from the request.
	ErrMissingParameter = errors.New("missing parameter")
)

var (
	// ValidTokenRegex matches only valid token characters (i.e. base64 characters).
	ValidTokenRegex = regexp.MustCompile(`^[a-zA-Z0-9-._~+/]+=*$`)
)

type authorizationHeaderType string

const (
	authorizationHeaderTypeBasic  authorizationHeaderType = "Basic"
	authorizationHeaderTypeBearer authorizationHeaderType = "Bearer"
	authorizationHeaderTypeDPoP   authorizationHeaderType = "DPoP"
)

// ParseBearerAuthorizationHeader parses the Authorization header field
// and returns the authorization token, if present and valid.
//
// The Authorization header should be in the form (RFC6750 2.1)
// b64token    = 1*( ALPHA / DIGIT /
// 					"-" / "." / "_" / "~" / "+" / "/" ) *"="
// credentials = "Bearer" 1*SP b64token
func ParseBearerAuthorizationHeader(authHeader string) (string, error) {
	return validateAuthorizationHeaderFormat(authorizationHeaderTypeBearer, authHeader)
}

// ParseDPoPAuthorizationHeader parses the Authorization header field
// and returns the DPoP proof, if present.
//
// The format follows the token68 syntax from RFC7235
// token68    = 1*( ALPHA / DIGIT /
// 					"-" / "." / "_" / "~" / "+" / "/" ) *"="
// credentials = "DPoP" 1*SP token68
func ParseDPoPAuthorizationHeader(authHeader string) (string, error) {
	return validateAuthorizationHeaderFormat(authorizationHeaderTypeDPoP, authHeader)
}

// ParseBasicAuthorizationHeader returns the client ID and secret
// sent via the HTTP Basic Authorization header, as defined in
// RFC 2617. An error is returned if the header could not be
// parsed or if either component is missing.
//
// We do not support client authentication via POST body.
// See RFC 6749 2.3.1
func ParseBasicAuthorizationHeader(authHeader string) (string, string, error) {
	// Validate and parse token value
	token, err := validateAuthorizationHeaderFormat(authorizationHeaderTypeBasic, authHeader)
	if err != nil {
		return "", "", err
	}

	// Retrieve client ID and secret
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", "", err
	}
	fields := strings.Split(string(decoded), ":")
	if len(fields) != 2 {
		return "", "", ErrInvalidToken
	}
	clientIDStr := fields[0]
	if clientIDStr == "" {
		return "", "", ErrMissingParameter
	}
	clientID, err := url.QueryUnescape(clientIDStr)
	if err != nil {
		return "", "", ErrInvalidToken
	}
	clientSecretStr := fields[1]
	clientSecret, err := url.QueryUnescape(clientSecretStr)
	if err != nil {
		return "", "", ErrInvalidToken
	}

	return string(clientID), string(clientSecret), nil
}

// validateAuthorizationHeaderFormat verifies that the Authorization header
// conforms to the format specified in *** and returns the base64 encoded token.
func validateAuthorizationHeaderFormat(typ authorizationHeaderType, authHeader string) (string, error) {
	if authHeader == "" {
		return "", ErrEmptyHeader
	}
	fields := strings.Fields(authHeader)
	if len(fields) != 2 {
		return "", ErrIncorrectHeaderFormat
	}
	if authorizationHeaderType(fields[0]) != typ {
		return "", ErrIncorrectHeaderFormat
	}

	token := fields[1]
	if !ValidTokenRegex.Match([]byte(token)) {
		return "", ErrInvalidToken
	}

	return token, nil
}
