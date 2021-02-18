package oauth

import (
	"time"

	"github.com/ftauth/ftauth/pkg/jwt"
	"github.com/gofrs/uuid"
)

// CreateProofToken creates a DPoP token for use at the given URI for the given HTTP method.
// These are single-use tokens good for 10 minutes, typically, and must be accompanied by a valid
// access token. They are not a substitute for an access token.
func CreateProofToken(privateKey *jwt.Key, httpMethod, httpURI string) (string, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return "", err
	}

	dpop := &jwt.Token{
		Header: &jwt.Header{
			Type:      jwt.TypeDPoP,
			Algorithm: privateKey.Algorithm,
			JWK:       privateKey.PublicJWK(),
		},
		Claims: &jwt.Claims{
			JwtID:      id.String(),
			HTTPMethod: httpMethod,
			HTTPURI:    httpURI,
			IssuedAt:   time.Now().Unix(),
		},
	}

	if err := dpop.Valid(); err != nil {
		return "", err
	}

	enc, err := dpop.Encode(privateKey)
	if err != nil {
		return "", err
	}

	return enc, nil
}
