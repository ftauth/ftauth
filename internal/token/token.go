package token

import (
	"fmt"
	"time"

	"github.com/ftauth/ftauth/internal/config"
	"github.com/ftauth/ftauth/pkg/jwt"
	"github.com/ftauth/ftauth/pkg/model"
	"github.com/ftauth/ftauth/pkg/util"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
)

// Type identifies the format of the token.
type Type string

// Supported token types
const (
	TypeBearer = "bearer"
	TypeDPoP   = "DPoP"
)

// IssueAccessToken provisions and signs a new JWT for the given client and scopes.
func IssueAccessToken(clientInfo *model.ClientInfo, user *model.User, scope string) (*jwt.Token, error) {
	if clientInfo == nil {
		return nil, util.ErrMissingParameter("clientInfo")
	}
	if err := clientInfo.IsValid(); err != nil {
		return nil, err
	}
	if user == nil {
		return nil, util.ErrMissingParameter("user")
	}
	if user.ID == "" {
		return nil, util.ErrInvalidParameter("user")
	}
	if err := clientInfo.ValidateScopes(scope); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	iat := now.Unix()
	exp := now.Add(time.Second * time.Duration(clientInfo.AccessTokenLife)).Unix()
	id, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	privateKey := config.Current.DefaultSigningKey()
	token := &jwt.Token{
		Header: &jwt.Header{
			Type:      jwt.TypeAccess,
			Algorithm: privateKey.Algorithm,
			KeyID:     privateKey.KeyID,
		},
		Claims: &jwt.Claims{
			Issuer:         "http://localhost:8080",
			Subject:        user.ID,
			Audience:       clientInfo.ID,
			ClientID:       clientInfo.ID,
			IssuedAt:       iat,
			ExpirationTime: exp,
			JwtID:          id.String(),
			Scope:          scope,
			CustomClaims: jwt.CustomClaims{
				"userInfo": user.ToUserData(),
				"https://ftauth.io": map[string]interface{}{
					"client_id": clientInfo.ID,
				},
			},
		},
	}
	_, err = token.Encode(privateKey)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// IssueRefreshToken creates a new refresh token for the given access token.
func IssueRefreshToken(clientInfo *model.ClientInfo, accessToken *jwt.Token) (*jwt.Token, error) {
	if clientInfo == nil {
		return nil, util.ErrMissingParameter("clientInfo")
	}
	if err := clientInfo.IsValid(); err != nil {
		return nil, err
	}
	if accessToken == nil {
		return nil, util.ErrMissingParameter("accessToken")
	}
	publicKey := config.Current.DefaultVerificationKey()
	if err := accessToken.Verify(publicKey); err != nil {
		return nil, errors.Wrap(err, "invalid access token")
	}
	if accessToken.Claims.JwtID == "" {
		return nil, fmt.Errorf("access token is missing jwt id")
	}

	now := time.Now().UTC()
	iat := now.Unix()
	exp := now.Add(time.Second * time.Duration(clientInfo.RefreshTokenLife)).Unix()
	id, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	token := &jwt.Token{
		Header: &jwt.Header{
			Type:      jwt.TypeAccess,
			Algorithm: publicKey.Algorithm,
			KeyID:     publicKey.KeyID,
		},
		Claims: &jwt.Claims{
			Issuer:         "http://localhost:8080",
			Subject:        accessToken.Claims.JwtID,
			Audience:       clientInfo.ID,
			ClientID:       clientInfo.ID,
			IssuedAt:       iat,
			ExpirationTime: exp,
			JwtID:          id.String(),
			Scope:          accessToken.Claims.Scope,
			CustomClaims: jwt.CustomClaims{
				"userInfo": model.UserData{ID: accessToken.Claims.Audience},
			},
		},
	}
	privateKey := config.Current.DefaultSigningKey()
	_, err = token.Encode(privateKey)
	if err != nil {
		return nil, err
	}

	return token, nil
}
