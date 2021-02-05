package database

import (
	"context"
	"encoding/json"
	"fmt"

	dgo "github.com/dgraph-io/dgo/v200"
	"github.com/dgraph-io/dgo/v200/protos/api"
	"github.com/ftauth/ftauth/internal/config"
	"github.com/ftauth/ftauth/pkg/model"
	"google.golang.org/grpc"
)

// DgraphDatabase holds connection to a Dgraph DB instance.
type DgraphDatabase struct {
	// The underlying gRPC connection.
	conn *grpc.ClientConn

	// The Dgraph client, wrapping conn.
	DB *dgo.Dgraph
}

// InitializeDgraphDatabase creates a new Dgraph database connection
// uses settings from the loaded configuration.
func InitializeDgraphDatabase() (*DgraphDatabase, error) {
	addr := fmt.Sprintf("%s:%s", config.Current.Database.Host, config.Current.Database.Port)
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}

	dgraphClient := dgo.NewDgraphClient(api.NewDgraphClient(conn))
	return &DgraphDatabase{DB: dgraphClient, conn: conn}, nil
}

// Seed initializes the database schema and creates all defaults.
func (db *DgraphDatabase) Seed() error {
	op := &api.Operation{}
	op.Schema = `
	
	`
	return nil
}

// Close handles closing all connections to the database.
func (db *DgraphDatabase) Close() error {
	return db.conn.Close()
}

// ListClients lists all clients in the database.
func (db *DgraphDatabase) ListClients(ctx context.Context, opt ...model.ClientOption) ([]*model.ClientInfo, error) {
	q := `{
		clients(func: type(Client)) {
			uid
			name            
			client_type            
			secret          
			secret_expiry    
			redirect_uris    
			scopes {
				name
				ruleset
			}         
			jwks_uri         
			logo_uri         
			grant_types      
			access_token_life 
			refresh_token_life
		}
	}`

	resp, err := db.DB.NewTxn().Query(ctx, q)
	if err != nil {
		return nil, err
	}

	var response struct {
		Clients []*model.ClientInfo `json:"clients"`
	}
	if err := json.Unmarshal(resp.Json, &response); err != nil {
		return nil, err
	}

	return response.Clients, nil
}

// GetClient returns client information for the given client ID.
func (db *DgraphDatabase) GetClient(ctx context.Context, clientID string) (*model.ClientInfo, error) {
	q := `query Client($clientID: string) {
		client(func: uid($clientID)) {
			uid
			name            
			client_type            
			secret          
			secret_expiry    
			redirect_uris    
			scopes {
				name
				ruleset
			}         
			jwks_uri         
			logo_uri         
			grant_types      
			access_token_life 
			refresh_token_life
		}
	}`
	vars := map[string]string{"clientID": clientID}

	resp, err := db.DB.NewTxn().QueryWithVars(ctx, q, vars)
	if err != nil {
		return nil, err
	}

	var response struct {
		Client model.ClientInfo `json:"client"`
	}
	if err := json.Unmarshal(resp.Json, &response); err != nil {
		return nil, err
	}

	return &response.Client, nil
}

// UpdateClient updates the client with the provided information.
func (db *DgraphDatabase) UpdateClient(ctx context.Context, clientUpdate model.ClientInfoUpdate) (*model.ClientInfo, error) {
	b, err := json.Marshal(clientUpdate)
	if err != nil {
		return nil, err
	}

	mu := &api.Mutation{
		SetJson:   b,
		CommitNow: true,
	}

	_, err = db.DB.NewTxn().Mutate(ctx, mu)
	if err != nil {
		return nil, err
	}

	return db.GetClient(ctx, clientUpdate.ID)
}

// RegisterClient registers the client with the provided information.
func (db *DgraphDatabase) RegisterClient(ctx context.Context, clientInfo *model.ClientInfo, opt model.ClientOption) (*model.ClientInfo, error) {
	b, err := json.Marshal(clientInfo)
	if err != nil {
		return nil, err
	}

	mu := &api.Mutation{
		CommitNow: true,
	}
	mu.SetJson = b

	resp, err := db.DB.NewTxn().Mutate(ctx, mu)
	if err != nil {
		return nil, err
	}

	// Create a copy and replace the UID
	co := *clientInfo
	co.ID = resp.Uids["client"]
	return &co, nil
}

// DeleteClient deletes the client from the database.
func (db *DgraphDatabase) DeleteClient(ctx context.Context, clientID string) error {
	del := struct {
		ID string `json:"uid"`
	}{
		ID: clientID,
	}
	b, err := json.Marshal(del)
	if err != nil {
		return err
	}

	mu := &api.Mutation{
		DeleteJson: b,
		CommitNow:  true,
	}

	_, err = db.DB.NewTxn().Mutate(ctx, mu)
	if err != nil {
		return err
	}

	return nil
}
