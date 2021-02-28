package database

import (
	"context"
	"time"

	"github.com/ftauth/ftauth/pkg/jwt"
	"github.com/ftauth/ftauth/pkg/model"
)

// DefaultTimeout is the default length of time to wait
// for a database operation to complete.
const DefaultTimeout = time.Second * 3

// // SQLDatabase is a database for communicating with an SQL server.
// type SQLDatabase struct {
// 	Type model.DatabaseType
// 	DB   *sqlx.DB
// }

// // Bindvar returns the query parameter type for this database for use with sqlx.
// func (db *SQLDatabase) Bindvar() int {
// 	switch db.Type {
// 	case model.DatabaseTypeOracle:
// 		return sqlx.NAMED
// 	case model.DatabaseTypePostgres:
// 		return sqlx.DOLLAR
// 	default:
// 		return sqlx.UNKNOWN
// 	}
// }

// Database handles all interactions with the data backend.
type Database interface {
	ClientDB
	AuthorizationDB
	AuthenticationDB
	DiscoveryDB
	ScopeDB
	GetDefaultAdminClient(ctx context.Context) (*model.ClientInfo, error)
	Close() error
}

// ClientDB handles interactions with the client database.
type ClientDB interface {
	ListClients(ctx context.Context, opt ...model.ClientOption) ([]*model.ClientInfo, error)
	GetClient(ctx context.Context, clientID string) (*model.ClientInfo, error)
	UpdateClient(ctx context.Context, client model.ClientInfoUpdate) (*model.ClientInfo, error)
	RegisterClient(ctx context.Context, clientInfo *model.ClientInfo, opt model.ClientOption) (*model.ClientInfo, error)
	DeleteClient(ctx context.Context, clientID string) error
}

// ScopeDB handles interactions with the scope database.
type ScopeDB interface {
	ListScopes(ctx context.Context) ([]*model.Scope, error)
	GetScope(ctx context.Context, scope string) (*model.Scope, error)
	RegisterScope(ctx context.Context, scope string) (*model.Scope, error)
	DeleteScope(ctx context.Context, scope string) error
}

// AuthorizationDB handles interactions with the authorization database,
// which may be the same as other databases or not.
type AuthorizationDB interface {
	CreateSession(ctx context.Context, request *model.AuthorizationRequest) error
	GetRequestInfo(ctx context.Context, requestID string) (*model.AuthorizationRequest, error)
	UpdateRequestInfo(ctx context.Context, requestInfo *model.AuthorizationRequest) error
	LookupSessionByCode(ctx context.Context, code string) (*model.AuthorizationRequest, error)
	RegisterToken(ctx context.Context, token *jwt.Token) error
	IsTokenSeen(ctx context.Context, token *jwt.Token) (bool, error)
	GetTokenByID(ctx context.Context, tokenID string) (string, error)
}

// AuthenticationDB handles interactions with the authentication databse,
// which may or may not be the same as other databases.
type AuthenticationDB interface {
	RegisterUser(ctx context.Context, user *model.User) error
	GetUserByID(ctx context.Context, id string) (*model.User, error)
	GetUserByUsername(ctx context.Context, username, clientID string) (*model.User, error)
	VerifyUsernameAndPassword(ctx context.Context, username, clientID, password string) error
}

// DiscoveryDB handles interactions with the discovery database, which contains
// metadata about this program. It should be the same as AuthorizationDB.
type DiscoveryDB interface{}
