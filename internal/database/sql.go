package database

import (
	"context"
	"fmt"
	"log"

	"github.com/dnys1/ftoauth/internal/config"
	"github.com/dnys1/ftoauth/internal/model"
	"github.com/dnys1/ftoauth/util/passwordutil"
	"github.com/dnys1/ftoauth/util/sqlutil"
	"github.com/gofrs/uuid"
	"github.com/jmoiron/sqlx"

	_ "github.com/godror/godror"       // Oracle DB driver
	_ "github.com/jackc/pgx/v4/stdlib" // The PostgreSQL driver
)

// InitializeOracleDB connects to a running Oracle DB instance.
func InitializeOracleDB() *sqlx.DB {
	db, err := sqlx.Connect("godror", `user="admin" password="Thisisasentence123!!" connectString="adwtest_medium"
		libDir="/Users/nysd2/bin/instantclient_19_8"`)
	if err != nil {
		log.Fatal(err)
	}

	return db
}

// InitializePostgresDB creates a new PostgreSQL database object.
func InitializePostgresDB() *sqlx.DB {
	host := config.Current.Database.Host
	port := config.Current.Database.Port
	dbname := config.Current.Database.DBName

	dsn := fmt.Sprintf("host=%s port=%s dbname=%s sslmode=disable", host, port, dbname)
	log.Printf("Connecting to database %s\n", dsn)

	db, err := sqlx.Connect("pgx", dsn)
	if err != nil {
		log.Fatalf("Error connecting to DB: %v", err)
	}

	if err := db.Ping(); err != nil {
		log.Fatalf("Error connecting to DB: %v", err)
	}

	return db
}

// GetClientInfo returns client information for the given client ID.
func (db *SQLDatabase) GetClientInfo(ctx context.Context, clientID string) (*model.ClientInfo, error) {
	query := sqlx.Rebind(db.Bindvar(), "SELECT * FROM clients WHERE id=?")
	var entity model.ClientInfoEntity
	err := db.DB.GetContext(ctx, &entity, query, clientID)
	if err != nil {
		return nil, err
	}
	ctx1, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	scopes := sqlutil.ParseArray(entity.Scopes)
	selectedScopes, err := db.GetScopes(ctx1, scopes...)
	if err != nil {
		return nil, err
	}
	return entity.ToModel(selectedScopes), nil
}

// GetScopes returns the selected scopes from the database. If scopes is empty, all scope entities are returned.
func (db *SQLDatabase) GetScopes(ctx context.Context, scopes ...string) ([]*model.Scope, error) {
	rows, err := db.DB.QueryxContext(ctx, "SELECT * FROM scopes")
	if err != nil {
		return nil, err
	}
	allScopes := make([]*model.Scope, 0)
	for rows.Next() {
		var scope model.Scope
		rows.StructScan(&scope)
		allScopes = append(allScopes, &scope)
	}
	if len(scopes) == 0 {
		return allScopes, nil
	}
	selectedScopes := make([]*model.Scope, 0)
	for _, scopeEnt := range allScopes {
		for _, scope := range scopes {
			if scopeEnt.Name == scope {
				selectedScopes = append(selectedScopes, scopeEnt)
			}
		}
	}
	return selectedScopes, nil
}

// CreateSession creates a session for the given client which includes
// the authorization code and code verifier information (PKCE), so that it can
// be verified later.
func (db *SQLDatabase) CreateSession(ctx context.Context, request *model.AuthorizationRequest) (string, error) {
	uuid, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
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
	_, err = db.DB.ExecContext(
		ctx,
		stmt,
		uuid.String(),
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
		return "", err
	}

	return uuid.String(), nil
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

// CreateUser registers a new user in the authentication database.
func (db *SQLDatabase) CreateUser(ctx context.Context, username, password string) error {
	hash, err := passwordutil.GeneratePasswordHash(password)
	if err != nil {
		return err
	}
	query := sqlx.Rebind(db.Bindvar(), `
		INSERT INTO users(email, password_hash)
		VALUES (?, ?)`,
	)
	_, err = db.DB.ExecContext(ctx, query, username, hash)
	if err != nil {
		return err
	}

	return nil
}

// VerifyUsernameAndPassword returns an error if the username and password
// combo do not match.
func (db *SQLDatabase) VerifyUsernameAndPassword(ctx context.Context, username, password string) error {
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
