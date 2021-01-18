package database

import (
	"context"
	"time"

	"github.com/ftauth/ftauth/internal/model"
	"github.com/ftauth/ftauth/jwt"
	"github.com/jmoiron/sqlx"
)

// DefaultTimeout is the default length of time to wait
// for a database operation to complete.
const DefaultTimeout = time.Second * 3

// SQLDatabase is a database for communicating with an SQL server.
type SQLDatabase struct {
	Type model.DatabaseType
	DB   *sqlx.DB
}

// Bindvar returns the query parameter type for this database for use with sqlx.
func (db *SQLDatabase) Bindvar() int {
	switch db.Type {
	case model.DatabaseTypeOracle:
		return sqlx.NAMED
	case model.DatabaseTypePostgres:
		return sqlx.DOLLAR
	default:
		return sqlx.UNKNOWN
	}
}

// Database handles all interactions with the data backend.
type Database interface {
	ClientDB
	AuthorizationDB
	AuthenticationDB
	DiscoveryDB
	Close() error
}

// ClientDB handles interactions with the client database.
type ClientDB interface {
	ListClients(ctx context.Context) ([]*model.ClientInfo, error)
	GetClient(ctx context.Context, clientID string) (*model.ClientInfo, error)
	UpdateClient(ctx context.Context, clientInfo *model.ClientInfo) (*model.ClientInfo, error)
	RegisterClient(ctx context.Context, clientInfo *model.ClientInfo, opt model.ClientOption) (*model.ClientInfo, error)
	DeleteClient(ctx context.Context, clientID string) error
}

// AuthorizationDB handles interactions with the authorization database,
// which may be the same as other databases or not.
type AuthorizationDB interface {
	CreateSession(ctx context.Context, request *model.AuthorizationRequest) error
	GetRequestInfo(ctx context.Context, requestID string) (*model.AuthorizationRequest, error)
	UpdateRequestInfo(ctx context.Context, requestInfo *model.AuthorizationRequest) error
	LookupSessionByCode(ctx context.Context, code string) (*model.AuthorizationRequest, error)
	RegisterTokens(ctx context.Context, accessToken, refreshToken *jwt.Token) (func() error, func() error, error)
	IsTokenSeen(ctx context.Context, token *jwt.Token) error
	GetTokenByID(ctx context.Context, tokenID string) (string, error)
}

// AuthenticationDB handles interactions with the authentication databse,
// which may or may not be the same as other databases.
type AuthenticationDB interface {
	CreateUser(ctx context.Context, id, username, passwordHash string) error
	GetUserByUsername(ctx context.Context, username string) (*model.User, error)
	VerifyUsernameAndPassword(ctx context.Context, username, password string) error
}

// DiscoveryDB handles interactions with the discovery database, which contains
// metadata about this program. It should be the same as AuthorizationDB.
type DiscoveryDB interface {
	DescribeSelf(ctx context.Context) (*model.AuthorizationServerMetadata, error)
}
