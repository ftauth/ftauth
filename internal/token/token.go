package token

import (
	"time"

	"github.com/dnys1/ftoauth/internal/config"
	"github.com/dnys1/ftoauth/internal/model"
	"github.com/dnys1/ftoauth/jwt"
	"github.com/google/uuid"
)

// Type identifies the format of the token.
type Type string

// Supported token types
const (
	TypeBearer = "bearer"
)

// IssueAccessToken provisions and signs a new JWT for the given client and scopes.
func IssueAccessToken(clientInfo *model.ClientInfo, scopes string) *jwt.Token {
	now := time.Now().UTC()
	iat := now.Unix()
	exp := now.Add(time.Second * time.Duration(clientInfo.AccessTokenLife)).Unix()
	id := uuid.New()
	token := &jwt.Token{
		Header: &jwt.Header{
			Type:      jwt.TypeAccess,
			Algorithm: jwt.AlgorithmRSASHA256,
			KeyID:     config.Current.OAuth.Tokens.PublicKey.KeyID,
		},
		Claims: &jwt.Claims{
			Issuer:         "http://localhost:8080",
			Subject:        clientInfo.ID,
			Audience:       "",
			ClientID:       clientInfo.ID,
			IssuedAt:       iat,
			ExpirationTime: exp,
			JwtID:          id.String(),
			Scope:          scopes,
		},
	}

	return token
}

// IssueRefreshToken creates a new refresh token for the given access token.
func IssueRefreshToken(clientInfo *model.ClientInfo, accessToken *jwt.Token) *jwt.Token {
	now := time.Now().UTC()
	iat := now.Unix()
	exp := now.Add(time.Second * time.Duration(clientInfo.RefreshTokenLife)).Unix()
	id := uuid.New()
	token := &jwt.Token{
		Header: &jwt.Header{
			Type:      jwt.TypeAccess,
			Algorithm: jwt.AlgorithmRSASHA256,
			KeyID:     config.Current.OAuth.Tokens.PublicKey.KeyID,
		},
		Claims: &jwt.Claims{
			Audience:       accessToken.Claims.JwtID,
			ClientID:       string(clientInfo.ID),
			IssuedAt:       iat,
			ExpirationTime: exp,
			JwtID:          id.String(),
			Scope:          accessToken.Claims.Scope,
		},
	}

	return token
}
