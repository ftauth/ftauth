package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	badger "github.com/dgraph-io/badger/v3"
	"github.com/ftauth/ftauth/pkg/jwt"
	"github.com/ftauth/ftauth/pkg/model"
	"github.com/ftauth/ftauth/pkg/util/passwordutil"
	"github.com/gofrs/uuid"
)

// BadgerDB holds a connection to a Badger backend.
type BadgerDB struct {
	Options     Options
	DB          *badger.DB
	AdminClient *model.ClientInfo
}

const (
	prefixClient   = "client"
	prefixUser     = "user"
	prefixToken    = "token"
	prefixDPoP     = "dpop"
	prefixMetadata = "metadata"
	prefixSession  = "session"
	prefixScope    = "scope"
)

func makeClientKey(id string) []byte {
	return makeKey(prefixClient, id)
}

func makeSessionKey(id string) []byte {
	return makeKey(prefixSession, id)
}

func makeUserKey(id string) []byte {
	return makeKey(prefixUser, id)
}

func makeMetadataKey(id uint64) []byte {
	return makeKey(prefixMetadata, fmt.Sprintf("%d", id))
}

func makeScopeKey(id string) []byte {
	return makeKey(prefixScope, id)
}

func makeTokenKey(id string) []byte {
	return makeKey(prefixToken, id)
}

func makeDPoPKey(id string) []byte {
	return makeKey(prefixDPoP, id)
}

func makeKey(prefix, id string) []byte {
	return []byte(fmt.Sprintf("%s_%s", prefix, id))
}

// Options specifies the FTAuth-specific options
// for initializing a DB instance
type Options struct {
	Path     string // Path to the DB storage
	InMemory bool   // Whether or not the DB is in memory
	SeedDB   bool   // Whether or not to seed the DB
}

// InitializeBadgerDB creates a new database with a Badger backend.
// Pass `true` to create an in-memory database (useful in tests, for example).
func InitializeBadgerDB(opts Options) (*BadgerDB, error) {
	if opts.Path == "" && !opts.InMemory {
		return nil, errors.New("missing path")
	}

	var badgerOpts badger.Options
	if opts.InMemory {
		badgerOpts = badger.DefaultOptions("").WithInMemory(true)
	} else {
		badgerOpts = badger.DefaultOptions(opts.Path)
	}
	db, err := badger.Open(badgerOpts)
	if err != nil {
		return nil, err
	}

	// TODO: If empty, seed with default client and server metadata.
	badgerDB := &BadgerDB{DB: db, Options: opts}

	if opts.SeedDB {
		if badgerDB.isEmpty() {
			admin, err := badgerDB.createAdminClient()
			if err != nil {
				return nil, err
			}
			badgerDB.AdminClient = admin
		} else {
			admin, err := badgerDB.getAdminClient()
			if err != nil {
				return nil, err
			}
			badgerDB.AdminClient = admin
		}
	}

	return badgerDB, nil
}

// Close handles closing all connections to the database.
func (db *BadgerDB) Close() error {
	return db.DB.Close()
}

// Reset clears all non-mandatory keys from the database.
func (db *BadgerDB) Reset() error {
	if !db.DB.Opts().InMemory {
		return fmt.Errorf("cannot clear db on disk")
	}
	return db.DB.Update(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			if item.UserMeta()>>7 == 0 {
				err := txn.Delete(item.Key())
				if err != nil {
					return err
				}
			}
		}

		return nil
	})
}

func (db *BadgerDB) isEmpty() (empty bool) {
	db.DB.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		it.Rewind()
		empty = !it.Valid()

		return nil
	})
	return
}

func (db *BadgerDB) createAdminClient() (*model.ClientInfo, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	adminClient := &model.ClientInfo{
		ID:           id.String(),
		Name:         "Admin",
		Type:         model.ClientTypePublic,
		RedirectURIs: []string{"localhost", "myapp://auth"},
		Scopes: []*model.Scope{
			{Name: "default"},
			{Name: "admin"},
		},
		GrantTypes: []model.GrantType{
			model.GrantTypeAuthorizationCode,
			model.GrantTypeClientCredentials,
			model.GrantTypeRefreshToken,
		},
		AccessTokenLife:  60 * 60,      // 1 hour
		RefreshTokenLife: 60 * 60 * 24, // 1 day
	}
	opt := model.ClientOptionAdmin | model.ClientOption(model.MasterSystemFlag)
	client, err := db.RegisterClient(context.Background(), adminClient, opt)
	if err != nil {
		return nil, err
	}

	userUUID, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	passwordHash, err := passwordutil.GeneratePasswordHash("password")
	if err != nil {
		return nil, err
	}
	err = db.CreateUser(context.Background(), userUUID.String(), "admin", passwordHash)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (db *BadgerDB) getAdminClient() (*model.ClientInfo, error) {
	opt := model.ClientOptionAdmin | model.ClientOption(model.MasterSystemFlag)
	clients, err := db.ListClients(context.Background(), opt)
	if err != nil {
		return nil, err
	}
	if len(clients) == 0 {
		return nil, badger.ErrKeyNotFound
	}
	return clients[0], nil
}

// ListClients lists all clients in the database.
func (db *BadgerDB) ListClients(ctx context.Context, opts ...model.ClientOption) ([]*model.ClientInfo, error) {
	clients := make([]*model.ClientInfo, 0)
	err := db.DB.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		prefix := []byte(prefixClient)
		var userMeta byte
		for _, opt := range opts {
			userMeta |= byte(opt)
		}
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()

			meta := item.UserMeta()
			if userMeta == 0 || userMeta&meta == meta {
				var client model.ClientInfo
				err := item.Value(func(v []byte) error {
					return json.Unmarshal(v, &client)
				})
				if err != nil {
					return err
				}
				clients = append(clients, &client)
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}
	return clients, nil
}

// GetClient returns client information for the given client ID.
func (db *BadgerDB) GetClient(ctx context.Context, clientID string) (client *model.ClientInfo, err error) {
	key := makeClientKey(clientID)
	err = db.DB.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}

		return item.Value(func(b []byte) error {
			return json.Unmarshal(b, &client)
		})
	})
	return
}

// UpdateClient updates the client with the provided information.
func (db *BadgerDB) UpdateClient(ctx context.Context, client *model.ClientInfo) (*model.ClientInfo, error) {
	key := makeClientKey(client.ID)
	err := db.DB.Update(func(txn *badger.Txn) error {
		b, err := json.Marshal(client)
		if err != nil {
			return err
		}
		return txn.Set(key, b)
	})
	if err != nil {
		return nil, err
	}
	return client, nil
}

// RegisterClient registers the client with the provided information.
func (db *BadgerDB) RegisterClient(ctx context.Context, clientInfo *model.ClientInfo, opt model.ClientOption) (*model.ClientInfo, error) {
	key := makeClientKey(clientInfo.ID)
	err := db.DB.Update(func(txn *badger.Txn) error {
		b, err := json.Marshal(clientInfo)
		if err != nil {
			return err
		}
		if opt == 0 {
			opt = model.ClientOptionNone
		}
		return txn.SetEntry(&badger.Entry{
			Key:      key,
			Value:    b,
			UserMeta: byte(opt),
		})
	})
	if err != nil {
		return nil, err
	}
	return clientInfo, nil
}

// DeleteClient deletes the client from the database.
func (db *BadgerDB) DeleteClient(ctx context.Context, clientID string) error {
	key := makeClientKey(clientID)
	return db.DB.Update(func(txn *badger.Txn) error {
		return txn.Delete(key)
	})
}

// CreateSession creates a session for the given client which includes
// the authorization code and code verifier information (PKCE), so that it can
// be verified later.
func (db *BadgerDB) CreateSession(ctx context.Context, request *model.AuthorizationRequest) error {
	key := makeSessionKey(request.ID)
	return db.DB.Update(func(txn *badger.Txn) error {
		b, err := json.Marshal(request)
		if err != nil {
			return err
		}
		return txn.Set(key, b)
	})
}

// GetRequestInfo returns the session info associated with this ID.
func (db *BadgerDB) GetRequestInfo(ctx context.Context, requestID string) (*model.AuthorizationRequest, error) {
	key := makeSessionKey(requestID)

	var request model.AuthorizationRequest
	err := db.DB.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}

		return item.Value(func(v []byte) error {
			return json.Unmarshal(v, &request)
		})
	})
	return &request, err
}

// UpdateRequestInfo updates the information pertinent to this request.
func (db *BadgerDB) UpdateRequestInfo(ctx context.Context, requestInfo *model.AuthorizationRequest) error {
	key := makeSessionKey(requestInfo.ID)
	return db.DB.Update(func(txn *badger.Txn) error {
		b, err := json.Marshal(requestInfo)
		if err != nil {
			return err
		}
		return txn.Set(key, b)
	})
}

// LookupSessionByCode retrieves a request session's data based off the authorization code.
func (db *BadgerDB) LookupSessionByCode(ctx context.Context, code string) (request *model.AuthorizationRequest, err error) {
	err = db.DB.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		prefix := []byte(prefixSession)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			var req model.AuthorizationRequest
			err := item.Value(func(v []byte) error {
				return json.Unmarshal(v, &req)
			})
			if err != nil {
				return err
			}

			if req.Code == code {
				request = &req
				return nil
			}
		}

		return badger.ErrKeyNotFound
	})
	return
}

// RegisterTokens saves the given tokens to the database, returning functions to either commit or rollback changes
// if the tokens cannot reach the end user, for example.
func (db *BadgerDB) RegisterTokens(ctx context.Context, accessToken, refreshToken *jwt.Token) (commit func() error, rollback func() error, err error) {
	accessKey := makeTokenKey(accessToken.Claims.JwtID)
	refreshKey := makeTokenKey(refreshToken.Claims.JwtID)

	txn := db.DB.NewTransaction(true)
	commit, rollback = txn.Commit, func() error { txn.Discard(); return nil }

	var accessTokenJwt string
	accessTokenJwt, err = accessToken.Raw()
	if err != nil {
		return
	}
	entry := &badger.Entry{
		Key:       accessKey,
		Value:     []byte(accessTokenJwt),
		ExpiresAt: uint64(accessToken.Claims.ExpirationTime),
	}
	err = txn.SetEntry(entry)
	if err != nil {
		return
	}

	var refreshTokenJwt string
	refreshTokenJwt, err = refreshToken.Raw()
	if err != nil {
		return
	}
	entry = &badger.Entry{
		Key:       refreshKey,
		Value:     []byte(refreshTokenJwt),
		ExpiresAt: uint64(refreshToken.Claims.ExpirationTime),
	}
	err = txn.SetEntry(entry)
	if err != nil {
		return
	}

	return
}

// GetTokenByID looks up and returns the encoded token corresponding to the provided ID.
func (db *BadgerDB) GetTokenByID(ctx context.Context, tokenID string) (token string, err error) {
	key := makeTokenKey(tokenID)
	err = db.DB.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}

		b, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}

		token = string(b)
		return nil
	})
	return
}

// IsTokenSeen returns true if the token has been before. If false, it firse
// records the token information so that subsequent calls return true.
func (db *BadgerDB) IsTokenSeen(ctx context.Context, token *jwt.Token) error {
	key := makeDPoPKey(token.Claims.JwtID)
	return db.DB.Update(func(txn *badger.Txn) error {
		_, err := txn.Get(key)
		if err != nil && err == badger.ErrKeyNotFound {
			// Write key to DB
			b, err := json.Marshal(token)
			if err != nil {
				return err
			}
			return txn.Set(key, b)
		}
		return errors.New("token previously seen")
	})
}

// CreateUser registers a new user in the authentication database.
func (db *BadgerDB) CreateUser(ctx context.Context, id, username, passwordHash string) error {
	key := makeUserKey(id)
	return db.DB.Update(func(txn *badger.Txn) error {
		b, err := json.Marshal(&model.User{
			ID:           id,
			Username:     strings.ToLower(username),
			PasswordHash: passwordHash,
		})
		if err != nil {
			return err
		}
		return txn.Set(key, b)
	})
}

// GetUserByID retrieves user's info based off an ID.
func (db *BadgerDB) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	key := makeUserKey(id)

	var user model.User
	err := db.DB.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}

		return item.Value(func(v []byte) error {
			return json.Unmarshal(v, &user)
		})
	})
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUserByUsername retrieves user's info based off a username.
func (db *BadgerDB) GetUserByUsername(ctx context.Context, username string) (user *model.User, err error) {
	err = db.DB.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		prefix := []byte(prefixUser)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()

			var _user model.User
			err := item.Value(func(v []byte) error {
				return json.Unmarshal(v, &_user)
			})
			if err != nil {
				return err
			}

			if _user.Username == strings.ToLower(username) {
				user = &_user
				return nil
			}
		}

		return badger.ErrKeyNotFound
	})
	return
}

// VerifyUsernameAndPassword returns an error if the username and password combo do not match what's in the DB.
func (db *BadgerDB) VerifyUsernameAndPassword(ctx context.Context, username, password string) error {
	user, err := db.GetUserByUsername(ctx, username)
	if err != nil {
		return err
	}
	if !passwordutil.CheckPasswordHash(password, user.PasswordHash) {
		return errors.New("invalid password")
	}
	return nil
}
