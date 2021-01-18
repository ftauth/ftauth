package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/ftauth/ftauth/internal/config"
	"github.com/ftauth/ftauth/jwt"
	"github.com/ftauth/ftauth/model"
	"github.com/ftauth/ftauth/util/passwordutil"
	"github.com/ftauth/ftauth/util/sqlutil"
	"github.com/gofrs/uuid"
	"github.com/jmoiron/sqlx"

	_ "github.com/godror/godror"       // Oracle DB driver
	_ "github.com/jackc/pgx/v4/stdlib" // The PostgreSQL driver
)

// InitializeOracleDB connects to a running Oracle DB instance.
func InitializeOracleDB() Database {
	db, err := sqlx.Connect("godror", `user="admin" password="Thisisasentence123!!" connectString="adwtest_medium"
		libDir="/Users/nysd2/bin/instantclient_19_8"`)
	if err != nil {
		log.Fatal(err)
	}

	return &SQLDatabase{Type: model.DatabaseTypePostgres, DB: db}
}

// InitializePostgresDB creates a new PostgreSQL database object.
func InitializePostgresDB() Database {
	host := config.Current.Database.Host
	port := config.Current.Database.Port
	dbname := config.Current.Database.DBName

	dsn := fmt.Sprintf("host=%s port=%d dbname=%s sslmode=disable", host, port, dbname)
	log.Printf("Connecting to database %s\n", dsn)

	db, err := sqlx.Connect("pgx", dsn)
	if err != nil {
		log.Fatalf("Error connecting to DB: %v", err)
	}

	if err := db.Ping(); err != nil {
		log.Fatalf("Error connecting to DB: %v", err)
	}

	return &SQLDatabase{Type: model.DatabaseTypePostgres, DB: db}
}

// Close handles closing all connections to the database.
func (db *SQLDatabase) Close() error {
	return db.DB.Close()
}

// ListClients lists all clients in the database.
func (db *SQLDatabase) ListClients(ctx context.Context) ([]*model.ClientInfo, error) {
	query := sqlx.Rebind(db.Bindvar(), "SELECT * FROM clients")

	var clientEntities []model.ClientInfoEntity
	err := db.DB.SelectContext(ctx, &clientEntities, query)
	if err != nil {
		return nil, err
	}

	allScopes, err := db.GetScopes(ctx)

	var clients []*model.ClientInfo
	for _, entity := range clientEntities {
		var scopes []*model.Scope
		for _, scope := range sqlutil.ParseArray(entity.Scopes) {
			scopes = append(scopes, allScopes[scope])
		}
		clients = append(clients, entity.ToModel(scopes))
	}

	return clients, nil
}

// RegisterClient registers the client with the provided information.
func (db *SQLDatabase) RegisterClient(ctx context.Context, clientInfo *model.ClientInfo, opt model.ClientOption) (*model.ClientInfo, error) {
	query := sqlx.Rebind(db.Bindvar(), `
		INSERT INTO
			clients(id, secret, redirect_uris, scopes, jwks_uri, logo_uri, grant_types, access_token_life, refresh_token_life)
		VALUES
			(?, ?, ?, ?, ?, ?, ?, ?, ?)`)

	uuid, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	var secret string
	if clientInfo.Type == model.ClientTypeConfidential {
		secret = model.GenerateAuthorizationCode()
	}
	entity := clientInfo.ToEntity()
	_, err = db.DB.ExecContext(
		ctx,
		query,
		uuid.String(),
		secret,
		entity.RedirectURIs,
		entity.Scopes,
		entity.JWKsURI,
		entity.LogoURI,
		entity.GrantTypes,
		entity.AccessTokenLife,
		entity.RefreshTokenLife,
	)
	if err != nil {
		return nil, err
	}

	return db.GetClient(ctx, uuid.String())
}

// GetClient returns client information for the given client ID.
func (db *SQLDatabase) GetClient(ctx context.Context, clientID string) (*model.ClientInfo, error) {
	query := sqlx.Rebind(db.Bindvar(), "SELECT * FROM clients WHERE id=?")
	var entity model.ClientInfoEntity
	err := db.DB.GetContext(ctx, &entity, query, clientID)
	if err != nil {
		return nil, err
	}
	ctx1, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	scopes := sqlutil.ParseArray(entity.Scopes)
	scopeMap, err := db.GetScopes(ctx1, scopes...)
	if err != nil {
		return nil, err
	}
	var selectedScopes []*model.Scope
	for _, scope := range scopeMap {
		selectedScopes = append(selectedScopes, scope)
	}
	return entity.ToModel(selectedScopes), nil
}

// UpdateClient updates the client with the provided information
func (db *SQLDatabase) UpdateClient(ctx context.Context, clientInfo *model.ClientInfo) (*model.ClientInfo, error) {
	query := sqlx.Rebind(db.Bindvar(), `
		UPDATE
			clients
		SET
			redirect_uris = ?,
			scopes = ?,
			jwks_uri = ?,
			logo_uri = ?,
			grant_types = ?,
			access_token_life = ?,
			refresh_token_life = ?
		WHERE
			id = ?`)

	var scopes []string
	for _, scope := range clientInfo.Scopes {
		scopes = append(scopes, scope.Name)
	}
	var grants []string
	for _, grant := range clientInfo.GrantTypes {
		grants = append(grants, string(grant))
	}
	_, err := db.DB.ExecContext(
		ctx,
		query,
		sqlutil.GenerateArrayString(clientInfo.RedirectURIs),
		sqlutil.GenerateArrayString(scopes),
		clientInfo.JWKsURI,
		clientInfo.LogoURI,
		sqlutil.GenerateArrayString(grants),
		clientInfo.AccessTokenLife,
		clientInfo.RefreshTokenLife,
		clientInfo.ID,
	)
	if err != nil {
		return nil, err
	}

	return db.GetClient(ctx, clientInfo.ID)
}

// DeleteClient deletes the client from the database.
func (db *SQLDatabase) DeleteClient(ctx context.Context, clientID string) error {
	query := sqlx.Rebind(db.Bindvar(), "DELETE FROM clients WHERE id = ?")
	_, err := db.DB.ExecContext(ctx, query, clientID)
	return err
}

// GetScopes returns the selected scopes from the database. If scopes is empty, all scope entities are returned.
func (db *SQLDatabase) GetScopes(ctx context.Context, scopes ...string) (map[string]*model.Scope, error) {
	rows, err := db.DB.QueryxContext(ctx, "SELECT * FROM scopes")
	if err != nil {
		return nil, err
	}
	allScopes := make(map[string]*model.Scope, 0)
	for rows.Next() {
		var scope model.Scope
		rows.StructScan(&scope)
		allScopes[scope.Name] = &scope
	}
	if len(scopes) == 0 {
		return allScopes, nil
	}
	selectedScopes := make(map[string]*model.Scope, 0)
	for _, scopeEnt := range allScopes {
		for _, scope := range scopes {
			if scopeEnt.Name == scope {
				selectedScopes[scope] = scopeEnt
			}
		}
	}
	return selectedScopes, nil
}

// CreateSession creates a session for the given client which includes
// the authorization code and code verifier information (PKCE), so that it can
// be verified later.
func (db *SQLDatabase) CreateSession(ctx context.Context, request *model.AuthorizationRequest) error {
	stmt := sqlx.Rebind(db.Bindvar(), `
	INSERT INTO requests (
		id,
		client_id,
		scope,
		state,
		redirect_uri,
		code, 
		code_challenge, 
		code_challenge_method, 
		exp
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	_, err := db.DB.ExecContext(
		ctx,
		stmt,
		request.ID,
		request.ClientID,
		request.Scope,
		request.State,
		request.RedirectURI,
		request.Code,
		request.CodeChallenge,
		request.CodeChallengeMethod,
		request.Expiry,
	)
	if err != nil {
		return err
	}

	return nil
}

// GetRequestInfo returns the session info associated with this ID.
func (db *SQLDatabase) GetRequestInfo(ctx context.Context, sessionID string) (*model.AuthorizationRequest, error) {
	query := sqlx.Rebind(db.Bindvar(), "SELECT * FROM requests WHERE id=?")
	var request model.AuthorizationRequest
	err := db.DB.GetContext(ctx, &request, query, sessionID)
	if err != nil {
		return nil, err
	}
	return &request, nil
}

// UpdateRequestInfo updates the information pertinent to this request.
func (db *SQLDatabase) UpdateRequestInfo(ctx context.Context, requestInfo *model.AuthorizationRequest) error {
	query := sqlx.Rebind(db.Bindvar(), `
		UPDATE
			requests
		SET
			"user" = ?
		WHERE
			id = ?
	`)
	_, err := db.DB.ExecContext(ctx, query, requestInfo.UserID, requestInfo.ID)
	return err
}

// LookupSessionByCode retrieves a request session's data based off the authorization code.
func (db *SQLDatabase) LookupSessionByCode(ctx context.Context, code string) (*model.AuthorizationRequest, error) {
	query := sqlx.Rebind(db.Bindvar(), "SELECT * from requests WHERE code=?")
	var request model.AuthorizationRequest
	err := db.DB.GetContext(ctx, &request, query, code)
	if err != nil {
		return nil, err
	}
	return &request, nil
}

// RegisterTokens saves the given tokens to the database, returning functions to either commit or rollback changes
// if the tokens cannot reach the end user, for example.
func (db *SQLDatabase) RegisterTokens(ctx context.Context, accessToken, refreshToken *jwt.Token) (func() error, func() error, error) {
	tx, err := db.DB.BeginTxx(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, nil, err
	}

	stmt := sqlx.Rebind(
		db.Bindvar(),
		`INSERT INTO 
			tokens(id, type, token, exp) 
		VALUES 
			(?, 'access', ?, ?), 
			(?, 'refresh', ?, ?)`,
	)

	accessJWT, err := accessToken.Raw()
	if err != nil {
		return nil, nil, err
	}
	refreshJWT, err := refreshToken.Raw()
	if err != nil {
		return nil, nil, err
	}
	_, err = tx.ExecContext(
		ctx,
		stmt,
		accessToken.Claims.JwtID,
		accessJWT,
		accessToken.Claims.ExpirationTime,
		refreshToken.Claims.JwtID,
		refreshJWT,
		refreshToken.Claims.ExpirationTime,
	)

	if err != nil {
		return nil, nil, err
	}

	return tx.Commit, tx.Rollback, nil
}

// GetTokenByID looks up and returns the encoded token corresponding to the provided ID.
func (db *SQLDatabase) GetTokenByID(ctx context.Context, tokenID string) (string, error) {
	query := sqlx.Rebind(db.Bindvar(), "SELECT token FROM tokens WHERE id = ?")
	var token string
	err := db.DB.SelectContext(ctx, &token, query, tokenID)
	if err != nil {
		return "", err
	}
	return token, nil
}

// CreateUser registers a new user in the authentication database.
func (db *SQLDatabase) CreateUser(ctx context.Context, id, username, password string) error {
	hash, err := passwordutil.GeneratePasswordHash(password)
	if err != nil {
		return err
	}
	query := sqlx.Rebind(db.Bindvar(), `
		INSERT INTO users(id, username, password_hash)
		VALUES (?, ?, ?)`,
	)
	_, err = db.DB.ExecContext(ctx, query, id, username, hash)
	if err != nil {
		return err
	}

	return nil
}

// GetUserByUsername retrieves user's info based off a username
func (db *SQLDatabase) GetUserByUsername(ctx context.Context, username string) (*model.User, error) {
	query := sqlx.Rebind(db.Bindvar(), "SELECT * FROM users WHERE username = ?")
	var user model.User
	err := db.DB.GetContext(ctx, &user, query, username)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// VerifyUsernameAndPassword returns an error if the username and password combo do not match what's in the DB.
func (db *SQLDatabase) VerifyUsernameAndPassword(ctx context.Context, username, password string) error {
	user, err := db.GetUserByUsername(ctx, username)
	if err != nil {
		return err
	}
	if !passwordutil.CheckPasswordHash(password, user.PasswordHash) {
		return errors.New("invalid password")
	}
	return nil
}

// DescribeSelf returns metadata about this server.
func (db *SQLDatabase) DescribeSelf(ctx context.Context) (*model.AuthorizationServerMetadata, error) {
	var entity model.AuthorizationServerMetadataOracleEntity
	err := db.DB.GetContext(ctx, &entity, "SELECT * FROM metadata WHERE issuer='demo'")
	if err != nil {
		return nil, err
	}
	return entity.NewAuthorizationServerMetadata(), nil
}

// IsTokenSeen returns true if the token has been before. If false, it firse
// records the token information so that subsequent calls return true.
func (db *SQLDatabase) IsTokenSeen(ctx context.Context, token *jwt.Token) error {
	query := sqlx.Rebind(db.Bindvar(), "SELECT * FROM seen WHERE id = ?")
	row := db.DB.QueryRowxContext(ctx, query, token.Claims.JwtID)
	if row.Err() != nil {
		insert := sqlx.Rebind(db.Bindvar(), "INSERT INTO seen(id, t) VALUES (?, ?)")
		_, err := db.DB.ExecContext(ctx, insert, token.Claims.JwtID, time.Now().UTC().Unix())
		if err != nil {
			return err
		}
		return row.Err()
	}
	return nil
}
