package fthttp

import (
	"errors"

	"github.com/ftauth/ftauth/pkg/jwt"
	"github.com/mitchellh/mapstructure"
)

const namespace = "https://ftauth.io"

// Errors
var (
	ErrMissingClaims = errors.New("missing ftauth claims")
	ErrInvalidClaims = errors.New("invalid ftauth claims")
)

// FTClaims hold user and client IDs in JWT tokens issued by the FTAuth server.
type FTClaims struct {
	UserID   string `mapstructure:"user_id"`
	ClientID string `mapstructure:"client_id"`
}

// ParseClaims extracts FTClaims from a JWT token, if present. It performs
// no verification or validation.
func ParseClaims(token *jwt.Token) (*FTClaims, error) {
	claims := token.Claims.CustomClaims
	ftauthClaims, ok := claims[namespace]
	if !ok {
		return nil, ErrMissingClaims
	}
	ftauthMap, ok := ftauthClaims.(map[string]interface{})
	if !ok {
		return nil, ErrInvalidClaims
	}

	var ftclaims FTClaims
	err := mapstructure.Decode(ftauthMap, &ftclaims)
	if err != nil {
		return nil, ErrInvalidClaims
	}

	return &ftclaims, nil
}
