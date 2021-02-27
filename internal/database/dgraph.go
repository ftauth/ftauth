package database

import (
	"context"
	"errors"
	"fmt"

	"github.com/ftauth/ftauth/internal/config"
	"github.com/ftauth/ftauth/internal/database/graphql"
	"github.com/ftauth/ftauth/pkg/jwt"
	"github.com/ftauth/ftauth/pkg/model"
)

// DgraphDatabase holds connection to a Dgraph DB instance.
type DgraphDatabase struct {
	// The Dgraph client, wrapping conn.
	client *graphql.Client

	// Admin client
	adminClient *model.ClientInfo
}

// DgraphOptions holds configuration options for the Dgraph database.
type DgraphOptions struct {
	URL      string
	APIKey   string
	Username string
	Password string
	SeedDB   bool
}

// Common errors
var (
	ErrClientNotFound = errors.New("client ID not found")
)

// InitializeDgraphDatabase creates a new Dgraph database connection
// uses settings from the loaded configuration.
func InitializeDgraphDatabase(ctx context.Context, opts DgraphOptions) (*DgraphDatabase, error) {
	addr := config.Current.Database.URL
	privateKey, err := config.Current.GetKeyForAlgorithm(jwt.AlgorithmRSASHA256, true)
	if err != nil {
		return nil, err
	}
	client, err := graphql.NewClient(addr, privateKey)
	if err != nil {
		return nil, err
	}
	db := &DgraphDatabase{
		client: client,
	}
	if opts.SeedDB {
		adminClient, err := db.Seed()
		if err != nil {
			return nil, err
		}

		db.adminClient = adminClient
	}

	return db, nil
}

// GetAdminClient returns the current admin client. It does not create one
// if it does not exist already.
func (db *DgraphDatabase) GetAdminClient() (*model.ClientInfo, error) {
	if db.adminClient != nil {
		return db.adminClient, nil
	}

	q := `
	%s
	query {
		queryScope(
			filter: {
				name: { eq: "admin" }
			}
		) {
			clients {
				...AllClientInfo
			}
		}
	}`

	q = fmt.Sprintf(q, model.AllClientInfo)

	var response struct {
		QueryScope []struct {
			Clients []*model.ClientInfo `json:"clients"`
		} `json:"queryScope"`
	}
	_, err := db.client.Do(context.Background(), &graphql.Request{
		Query:    q,
		Response: &response,
	})
	if err != nil {
		return nil, err
	}
	if len(response.QueryScope) != 1 {
		return nil, ErrClientNotFound
	}
	if len(response.QueryScope[0].Clients) == 0 {
		return nil, ErrClientNotFound
	}

	return response.QueryScope[0].Clients[0], nil
}

// Seed initializes the database schema and creates all defaults.
func (db *DgraphDatabase) Seed() (*model.ClientInfo, error) {
	// Get currently registered admin, if present
	admin, err := db.GetAdminClient()
	if err == nil {
		return admin, nil
	} else if err != ErrClientNotFound {
		return nil, err
	}

	// Create admin client if absent
	// TODO: Complete DB
	// return createAdminClient(db)
	return nil, nil
}

// Close handles closing all connections to the database.
func (db *DgraphDatabase) Close() error {
	return nil
}

// ListClients lists all clients in the database.
func (db *DgraphDatabase) ListClients(ctx context.Context, opt ...model.ClientOption) ([]*model.ClientInfo, error) {
	q := `
	%s
	query {
		queryClientInfo {
			...AllClientInfo
		}
	}`

	q = fmt.Sprintf(q, model.AllClientInfo)

	var response struct {
		Clients []*model.ClientInfo `json:"clients"`
	}
	_, err := db.client.Do(ctx, &graphql.Request{
		Query:    q,
		Response: &response,
	})
	if err != nil {
		return nil, err
	}

	return response.Clients, nil
}

// GetClient returns client information for the given client ID.
func (db *DgraphDatabase) GetClient(ctx context.Context, clientID string) (*model.ClientInfo, error) {
	q := `
	%s
	query Client($clientID: string) {
		getClientInfo(id: $clientID) {
			...AllClientInfo
		}
	}`
	q = fmt.Sprintf(q, model.AllClientInfo)

	vars := map[string]interface{}{"clientID": clientID}

	var response struct {
		Client *model.ClientInfo `json:"getClientInfo"`
	}
	_, err := db.client.Do(ctx, &graphql.Request{
		Query:     q,
		Variables: vars,
		Response:  &response,
	})
	if err != nil {
		return nil, err
	}
	if response.Client == nil {
		return nil, ErrClientNotFound
	}

	return response.Client, nil
}

// UpdateClient updates the client with the provided information.
func (db *DgraphDatabase) UpdateClient(ctx context.Context, clientUpdate model.ClientInfoUpdate) (*model.ClientInfo, error) {
	mu := `
	mutation {
		updateClientInfo(input: {
			set: %s
			filter: {
				id: {eq: "%s"}
			}
		}) {
			numUids
		}
	}`

	mu = fmt.Sprintf(mu, clientUpdate.GQL(), clientUpdate.ID)

	var response struct {
		UpdateClientInfo struct {
			NumUIDs int `json:"numUids"`
		} `json:"updateClientInfo"`
	}
	_, err := db.client.Do(ctx, &graphql.Request{
		Query:    mu,
		Response: &response,
	})
	if err != nil {
		return nil, err
	}
	if response.UpdateClientInfo.NumUIDs != 1 {
		return nil, ErrClientNotFound
	}

	return db.GetClient(ctx, clientUpdate.ID)
}

// RegisterClient registers the client with the provided information.
func (db *DgraphDatabase) RegisterClient(ctx context.Context, clientInfo *model.ClientInfo, opt model.ClientOption) (*model.ClientInfo, error) {
	mu := `
	%s
	mutation {
		addClientInfo(
		  input: %s
		) {
		  clientInfo {
			...AllClientInfo
		  }
		}
	  }
	`

	mu = fmt.Sprintf(mu, model.AllClientInfo, clientInfo.GQL())

	var response struct {
		AddClientInfo struct {
			ClientInfo []*model.ClientInfo `json:"clientInfo"`
		} `json:"addClientInfo"`
	}
	_, err := db.client.Do(ctx, &graphql.Request{
		Query:    mu,
		Response: &response,
	})
	if err != nil {
		return nil, err
	}
	if response.AddClientInfo.ClientInfo == nil || len(response.AddClientInfo.ClientInfo) != 1 {
		return nil, errors.New("error saving client")
	}

	clientInfo = response.AddClientInfo.ClientInfo[0]

	return clientInfo, clientInfo.IsValid()
}

// DeleteClient deletes the client from the database.
func (db *DgraphDatabase) DeleteClient(ctx context.Context, clientID string) error {
	d := `
	mutation {
		deleteClientInfo(
			filter: {
				id: { eq: "%s" }
			}
		) {
			numUids
		}
	}`

	d = fmt.Sprintf(d, clientID)

	var response struct {
		DeleteClientInfo struct {
			NumUIDs int `json:"numUids"`
		} `json:"deleteClientInfo"`
	}
	_, err := db.client.Do(ctx, &graphql.Request{
		Query:    d,
		Response: &response,
	})
	if err != nil {
		return err
	}
	if response.DeleteClientInfo.NumUIDs != 1 {
		return ErrClientNotFound
	}

	return nil
}
