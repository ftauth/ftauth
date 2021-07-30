package fthttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

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

// DownloadKeyset retrieves and deserializes the JWKS at the given URL.
func DownloadKeyset(ctx context.Context, jwksUrl string) (*jwt.KeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksUrl, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bb, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s (%d): %s", http.StatusText(resp.StatusCode), resp.StatusCode, bb)
	}

	keySet, err := jwt.DecodeKeySet(string(bb))
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling keyset: %v", err)
	}
	return keySet, nil
}

// ValidateToken asserts valid FTAuth claims in the token and
// verifies the signature against the keyset of the URL provided.
func ValidateToken(ctx context.Context, encoded string, jwksUrl string) (*FTClaims, error) {
	// Decode and verify JWT token
	token, err := jwt.Decode(encoded)
	if err != nil {
		return nil, err
	}

	keySet, err := DownloadKeyset(ctx, jwksUrl)
	if err != nil {
		return nil, err
	}

	verificationKey, err := keySet.KeyForAlgorithm(token.Header.Algorithm)
	if err != nil {
		return nil, err
	}
	err = token.Verify(verificationKey)
	if err != nil {
		return nil, err
	}
	if token.IsExpired() {
		return nil, ErrExpiredToken
	}

	return ParseClaims(token)
}
