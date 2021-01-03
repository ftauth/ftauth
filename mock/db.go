package mock

import (
	"context"
	"errors"
	"time"

	"github.com/dnys1/ftoauth/internal/config"
	"github.com/dnys1/ftoauth/internal/model"
	"github.com/dnys1/ftoauth/jwt"
	"github.com/gofrs/uuid"
)

// DB contains mocks for all database functions.
type DB struct{}

func createUUID() string {
	id, _ := uuid.NewV4()
	return id.String()
}

var (
	errNotFound = errors.New("not found")
)

// Clients holds mock clients for testing
var Clients = []*model.ClientInfo{
	{
		ID:           createUUID(),
		Name:         "Public Client",
		Type:         model.ClientTypePublic,
		Secret:       "",
		SecretExpiry: time.Unix(0, 0),
		RedirectURIs: []string{"localhost"},
		Scopes: []*model.Scope{
			{
				Name: "default",
			},
		},
		JWKsURI: "http://localhost:8000/jwks.json",
		LogoURI: "",
		GrantTypes: []model.GrantType{
			model.GrantTypeAuthorizationCode,
			model.GrantTypeClientCredentials,
			model.GrantTypeRefreshToken,
		},
		AccessTokenLife:  3600,
		RefreshTokenLife: 86400,
	},
}

var sessions = make(map[string]*model.AuthorizationRequest)
var tokens = make(map[string]*jwt.Token)
var dpop = make([]string, 0)

// ListClients lists mock clients.
func (db *DB) ListClients(ctx context.Context) ([]*model.ClientInfo, error) {
	return Clients, nil
}

// GetClient gets a mock client.
func (db *DB) GetClient(ctx context.Context, clientID string) (*model.ClientInfo, error) {
	for _, client := range Clients {
		if client.ID == clientID {
			return client, nil
		}
	}
	return nil, errNotFound
}

// UpdateClient updates a mock client.
func (db *DB) UpdateClient(ctx context.Context, clientInfo *model.ClientInfo) (*model.ClientInfo, error) {
	for i, client := range Clients {
		if client.ID == clientInfo.ID {
			Clients[i] = clientInfo
			return clientInfo, nil
		}
	}
	return nil, errNotFound
}

// RegisterClient creates a new mock client.
func (db *DB) RegisterClient(ctx context.Context, clientInfo *model.ClientInfo) (*model.ClientInfo, error) {
	Clients = append(Clients, clientInfo)
	return clientInfo, nil
}

// DeleteClient deletes a mock client.
func (db *DB) DeleteClient(ctx context.Context, clientID string) error {
	var i int
	found := false
	for ; i < len(Clients); i++ {
		if clientID == Clients[i].ID {
			found = true
			break
		}
	}
	if found {
		Clients = append([]*model.ClientInfo{}, Clients[:i]...)
		if i+1 < len(Clients)-1 {
			Clients = append(Clients, Clients[i+1:]...)
		}
	}
	return nil
}

// CreateSession creates a mock session
func (db *DB) CreateSession(ctx context.Context, request *model.AuthorizationRequest) (string, error) {
	id := createUUID()
	sessions[id] = request
	return id, nil
}

// GetRequestInfo returns mock request info
func (db *DB) GetRequestInfo(ctx context.Context, requestID string) (*model.AuthorizationRequest, error) {
	if req, ok := sessions[requestID]; ok {
		return req, nil
	}
	return nil, errNotFound
}

// UpdateRequestInfo updates mock request info
func (db *DB) UpdateRequestInfo(ctx context.Context, requestInfo *model.AuthorizationRequest) error {
	if _, ok := sessions[requestInfo.ID]; ok {
		sessions[requestInfo.ID] = requestInfo
		return nil
	}
	return errNotFound
}

// LookupSessionByCode looks up a mock session by authorization code
func (db *DB) LookupSessionByCode(ctx context.Context, code string) (*model.AuthorizationRequest, error) {
	for _, session := range sessions {
		if session.Code == code {
			return session, nil
		}
	}
	return nil, errNotFound
}

// RegisterTokens adds tokens to the mock DB
func (db *DB) RegisterTokens(ctx context.Context, accessToken, refreshToken *jwt.Token) (func() error, func() error, error) {
	tokens[accessToken.Claims.JwtID] = accessToken
	tokens[refreshToken.Claims.JwtID] = refreshToken
	f := func() error {
		return nil
	}
	return f, f, nil
}

// IsTokenSeen returns true if the mock db includes the token. Otherwise, it adds it.
func (db *DB) IsTokenSeen(ctx context.Context, token *jwt.Token) error {
	for _, seen := range dpop {
		if seen == token.Claims.JwtID {
			return nil
		}
	}
	dpop = append(dpop, token.Claims.JwtID)
	return errNotFound
}

// GetTokenByID returns the token based off its ID
func (db *DB) GetTokenByID(ctx context.Context, tokenID string) (string, error) {
	if token, ok := tokens[tokenID]; ok {
		return token.Encode(config.Current.OAuth.Tokens.PrivateKey)
	}
	return "", errNotFound
}
