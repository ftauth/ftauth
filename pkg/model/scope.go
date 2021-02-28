package model

import (
	_ "embed" // GraphQL embeds
	"errors"
	"regexp"
	"strings"
)

var (
	// ValidScopeTokenRegex matches valid scope tokens as defined
	// in [RFC 6749 3.3](https://tools.ietf.org/html/rfc6749#section-3.3)
	ValidScopeTokenRegex = regexp.MustCompile(`^[\x21\x23-\x5B\x5D-\x7E]+$`)

	// ErrInvalidScopeFormat means the provided scope does not
	// conform to the proper format.
	ErrInvalidScopeFormat = errors.New("invalid scope format")

	// ErrInvalidScopeTokenFormat means the provided scope token
	// does not conform to the proper format.
	ErrInvalidScopeTokenFormat = errors.New("invalid scope token format")

	// ErrEmptyScope means no scope was provided.
	ErrEmptyScope = errors.New("empty scope")
)

// GraphQL embeds
var (
	//go:embed gql/fragments/AllScopeInfo.graphql
	AllScopeInfo string
)

// ParseScope ensures the provided scope string contains
// a valid list of scope tokens. If so, the list of scope
// tokens is returned. If not, an error is returned.
func ParseScope(scope string) ([]string, error) {
	fields := strings.Fields(scope)
	if len(fields) == 0 {
		return []string{}, nil
	}

	scopeTokens := make([]string, 0)
	for _, scopeToken := range fields {
		if scopeToken == "" {
			return nil, ErrEmptyScope
		}
		if ValidScopeTokenRegex.MatchString(scopeToken) {
			scopeTokens = append(scopeTokens, scopeToken)
		} else {
			return nil, ErrInvalidScopeTokenFormat
		}
	}

	return scopeTokens, nil
}

// ScopesToModel converts a string array to Scope model objects.
func ScopesToModel(scopes []string) []*Scope {
	var scopeModels []*Scope
	for _, scope := range scopes {
		scopeModels = append(scopeModels, &Scope{Name: scope})
	}
	return scopeModels
}
