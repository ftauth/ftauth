package database

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/dgraph-io/dgo/v210"
	"github.com/dgraph-io/dgo/v210/protos/api"
	"github.com/ftauth/ftauth/internal/config"
	"github.com/ftauth/ftauth/pkg/dgraph"
	"github.com/ftauth/ftauth/pkg/graphql"
	"github.com/ftauth/ftauth/pkg/jwt"
	"github.com/ftauth/ftauth/pkg/model"
	"github.com/ftauth/ftauth/pkg/util/passwordutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// DgraphDatabase holds connection to a Dgraph DB instance.
type DgraphDatabase struct {
	// The Dgraph client, wrapping conn.
	client *dgraph.GraphQLClient

	// Admin client
	adminClient *model.ClientInfo

	// Dgraph gRPC connection params
	grpcConn  *grpc.ClientConn
	dgoClient *dgo.Dgraph
}

// From dgo: gRPC authorization credentials
type authCreds struct {
	token string
}

func (a *authCreds) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{"Authorization": a.token}, nil
}

func (a *authCreds) RequireTransportSecurity() bool {
	return true
}

// DgraphOptions holds configuration options for the Dgraph database.
type DgraphOptions struct {
	GraphQLEndpoint string
	GrpcEndpoint    string
	APIKey          string
	Username        string
	Password        string
	SeedDB          bool
	DropAll         bool // Whether to drop all data
}

// Common errors
var (
	ErrNotFound = errors.New("key not found")
)

func setupDgoClient(ctx context.Context, opts *config.DatabaseConfig) (*grpc.ClientConn, *dgo.Dgraph, error) {
	grpcURL, err := url.Parse(opts.Grpc)
	if err != nil {
		return nil, nil, err
	}
	if grpcURL.Port() == "" {
		grpcURL.Host = fmt.Sprintf("%s:%d", grpcURL.Hostname(), 9080)
	}

	var dialOpts []grpc.DialOption
	if grpcURL.Scheme == "https" {
		// From dgo
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, nil, err
		}

		creds := credentials.NewClientTLSFromCert(pool, "")

		dialOpts = []grpc.DialOption{
			grpc.WithTransportCredentials(creds),
			grpc.WithPerRPCCredentials(&authCreds{opts.APIKey}),
		}
	} else {
		dialOpts = []grpc.DialOption{
			grpc.WithInsecure(),
		}
	}

	grpcURL.Scheme = ""
	grpcConn, err := grpc.DialContext(
		ctx,
		grpcURL.Host,
		dialOpts...,
	)
	if err != nil {
		return nil, nil, err
	}
	dgraphClient := dgo.NewDgraphClient(api.NewDgraphClient(grpcConn))

	return grpcConn, dgraphClient, nil
}

// NewDgraphDatabase creates a new Dgraph database connection
// uses settings from the loaded configuration.
func NewDgraphDatabase(ctx context.Context, opts *config.DatabaseConfig) (*DgraphDatabase, error) {
	if opts == nil {
		opts = config.Current.Database
	}
	privateKey, err := config.Current.GetKeyForAlgorithm(jwt.AlgorithmRSASHA256, true)
	if err != nil {
		return nil, err
	}
	client, err := dgraph.NewClient(opts.URL, privateKey, opts.APIKey, map[string]interface{}{
		"ROLE": "SUPERUSER",
	})
	if err != nil {
		return nil, err
	}
	grpcConn, dgoClient, err := setupDgoClient(ctx, opts)
	if err != nil {
		return nil, err
	}

	db := &DgraphDatabase{
		client:    client,
		grpcConn:  grpcConn,
		dgoClient: dgoClient,
	}

	// Check DB health via GraphQL endpoint
	{
		ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()

		err = db.client.Ping(ctx)
		if err != nil {
			return nil, err
		}
	}

	if opts.DropAll {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		err = db.DropAll(ctx)
		if err != nil {
			return nil, err
		}
	}

	if opts.SeedDB {
		schema, err := model.Schema()
		if err != nil {
			return nil, err
		}

		{
			ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()

			err := client.UpdateSchema(ctx, schema)
			if err != nil {
				return nil, err
			}
		}

		{
			ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
			defer cancel()

			adminClient, err := db.Seed(ctx)
			if err != nil {
				return nil, err
			}

			db.adminClient = adminClient
		}
	}

	return db, nil
}

// GetDefaultAdminClient returns the current admin client. It does not create one
// if it does not exist already.
func (db *DgraphDatabase) GetDefaultAdminClient(ctx context.Context) (*model.ClientInfo, error) {
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
	_, err := db.client.Do(ctx, &graphql.Request{
		Query:    q,
		Response: &response,
	})
	if err != nil {
		return nil, err
	}
	if len(response.QueryScope) == 0 {
		return nil, ErrNotFound
	}
	if len(response.QueryScope[0].Clients) == 0 {
		return nil, ErrNotFound
	}

	return response.QueryScope[0].Clients[0], nil
}

// Seed initializes the database schema and creates all defaults.
func (db *DgraphDatabase) Seed(ctx context.Context) (*model.ClientInfo, error) {
	// Get currently registered admin, if present
	admin, err := db.GetDefaultAdminClient(ctx)
	if err == nil {
		return admin, nil
	} else if err != ErrNotFound {
		return nil, err
	}

	// Create admin client if absent
	return CreateAdminClient(ctx, db)
}

// Close handles closing all connections to the database.
func (db *DgraphDatabase) Close() error {
	return db.grpcConn.Close()
}

// clear drops all data from the database.
func (db *DgraphDatabase) DropAll(ctx context.Context) error {
	db.adminClient = nil
	op := &api.Operation{
		DropOp:          api.Operation_DATA,
		RunInBackground: false,
	}
	return db.dgoClient.Alter(ctx, op)
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
		Clients []*model.ClientInfo `json:"queryClientInfo"`
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
	query {
		getClientInfo(id: "%s") {
			...AllClientInfo
		}
	}`
	q = fmt.Sprintf(q, model.AllClientInfo, clientID)

	var response struct {
		Client *model.ClientInfo `json:"getClientInfo"`
	}
	_, err := db.client.Do(ctx, &graphql.Request{
		Query:    q,
		Response: &response,
	})
	if err != nil {
		return nil, err
	}
	if response.Client == nil {
		return nil, ErrNotFound
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
	if response.UpdateClientInfo.NumUIDs == 0 {
		return nil, ErrNotFound
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
	if len(response.AddClientInfo.ClientInfo) == 0 {
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
	if response.DeleteClientInfo.NumUIDs == 0 {
		return ErrNotFound
	}

	return nil
}

// ListScopes returns all scopes in the database.
func (db *DgraphDatabase) ListScopes(ctx context.Context) ([]*model.Scope, error) {
	q := `
	%s
	query {
		queryScope {
			...AllScopeInfo
		}
	}`

	q = fmt.Sprintf(q, model.AllScopeInfo)

	var response struct {
		Scopes []*model.Scope `json:"queryScope"`
	}
	_, err := db.client.Do(ctx, &graphql.Request{
		Query:    q,
		Response: &response,
	})
	if err != nil {
		return nil, err
	}

	return response.Scopes, nil
}

// GetScope retrieves a scope by name.
func (db *DgraphDatabase) GetScope(ctx context.Context, scopeName string) (*model.Scope, error) {
	q := `
	%s
	query {
		getScope(name: "%s") {
			...AllScopeInfo
		}
	}`

	q = fmt.Sprintf(q, model.AllScopeInfo, scopeName)

	var response struct {
		Scope *model.Scope `json:"getScope"`
	}
	_, err := db.client.Do(ctx, &graphql.Request{
		Query:    q,
		Response: &response,
	})
	if err != nil {
		return nil, err
	}
	if response.Scope == nil {
		return nil, ErrNotFound
	}

	return response.Scope, nil
}

// RegisterScope adds a new scope to the database.
func (db *DgraphDatabase) RegisterScope(ctx context.Context, scopeName string) (*model.Scope, error) {
	mu := `
	mutation {
		addScope(
			input: %s
		) {
			numUids
		}
	}`

	scope := &model.Scope{Name: scopeName}
	mu = fmt.Sprintf(mu, scope.GQL())

	var response struct {
		AddScope struct {
			NumUIDs int `json:"numUids"`
		} `json:"addScope"`
	}
	_, err := db.client.Do(ctx, &graphql.Request{
		Query:    mu,
		Response: &response,
	})
	if err != nil {
		return nil, err
	}
	if response.AddScope.NumUIDs == 0 {
		return nil, errors.New("error saving scope")
	}

	return scope, nil
}

// DeleteScope removes a scope from the database.
func (db *DgraphDatabase) DeleteScope(ctx context.Context, scope string) error {
	mu := `
	mutation {
		deleteScope(
			filter: {
				name: {eq: "%s"}
			}
		) {
			numUids
		}
	}`

	mu = fmt.Sprintf(mu, scope)

	var response struct {
		DeleteScope struct {
			NumUIDs int `json:"numUids"`
		} `json:"deleteScope"`
	}
	_, err := db.client.Do(ctx, &graphql.Request{
		Query:    mu,
		Response: &response,
	})
	if err != nil {
		return err
	}
	if response.DeleteScope.NumUIDs == 0 {
		return errors.New("error deleting scope")
	}

	return nil
}

// CreateSession creates a session for the given client which includes
// the authorization code and code verifier information (PKCE), so that it can
// be verified later.
func (db *DgraphDatabase) CreateSession(ctx context.Context, request *model.AuthorizationRequest) error {
	mu := `
	mutation {
		addAuthorizationRequest(
			input: %s
		) {
			numUids
		}
	}`

	mu = fmt.Sprintf(mu, request.GQL())

	var response struct {
		Response struct {
			NumUIDs int `json:"numUids"`
		} `json:"addAuthorizationRequest"`
	}
	_, err := db.client.Do(ctx, &graphql.Request{
		Query:    mu,
		Response: &response,
	})
	if err != nil {
		return err
	}
	if response.Response.NumUIDs == 0 {
		return errors.New("error creating session")
	}

	return nil
}

// GetRequestInfo returns the session info associated with this ID.
func (db *DgraphDatabase) GetRequestInfo(ctx context.Context, requestID string) (*model.AuthorizationRequest, error) {
	q := `
	%s
	query {
		getAuthorizationRequest(id: "%s") {
			...AllAuthorizationRequestInfo
		}
	}`

	q = fmt.Sprintf(q, model.AllAuthorizationRequestInfo, requestID)

	var response struct {
		AuthorizationRequest *model.AuthorizationRequest `json:"getAuthorizationRequest"`
	}
	_, err := db.client.Do(ctx, &graphql.Request{
		Query:    q,
		Response: &response,
	})
	if err != nil {
		return nil, err
	}
	if response.AuthorizationRequest == nil {
		return nil, ErrNotFound
	}

	return response.AuthorizationRequest, nil
}

// UpdateRequestInfo updates the information pertinent to this request.
func (db *DgraphDatabase) UpdateRequestInfo(ctx context.Context, requestInfo *model.AuthorizationRequest) error {
	mu := `
	mutation {
		updateAuthorizationRequest(
			input: {
				set: %s
				filter: {
					id: {eq: "%s"}
				}
			}
		) {
			numUids
		}
	}
	`

	up := requestInfo.ToUpdate()
	mu = fmt.Sprintf(mu, up.GQL(), requestInfo.ID)

	var response struct {
		Response struct {
			NumUIDs int `json:"numUids"`
		} `json:"updateAuthorizationRequest"`
	}
	_, err := db.client.Do(ctx, &graphql.Request{
		Query:    mu,
		Response: &response,
	})
	if err != nil {
		return err
	}
	if response.Response.NumUIDs == 0 {
		return errors.New("error updating request")
	}

	return nil
}

// LookupSessionByCode retrieves a request session's data based off the authorization code.
func (db *DgraphDatabase) LookupSessionByCode(ctx context.Context, code string) (*model.AuthorizationRequest, error) {
	q := `
	%s
	query {
		queryAuthorizationRequest(
			filter: {
				code: {eq: "%s"}
			}
		) {
			...AllAuthorizationRequestInfo
		}
	}
	`

	q = fmt.Sprintf(q, model.AllAuthorizationRequestInfo, code)

	var response struct {
		AuthorizationRequests []*model.AuthorizationRequest `json:"queryAuthorizationRequest"`
	}
	_, err := db.client.Do(ctx, &graphql.Request{
		Query:    q,
		Response: &response,
	})
	if err != nil {
		return nil, err
	}
	if len(response.AuthorizationRequests) == 0 {
		return nil, ErrNotFound
	}

	return response.AuthorizationRequests[0], nil
}

// RegisterToken saves the given tokens to the database for later reference.
func (db *DgraphDatabase) RegisterToken(ctx context.Context, token *jwt.Token) error {
	raw, err := token.Raw()
	if err != nil {
		return err
	}
	return db.registerJWT(ctx, token.Claims.JwtID, raw)
}

func (db *DgraphDatabase) registerJWT(ctx context.Context, id, jwt string) error {
	mu := `
	mutation {
		addToken(
			input: {
				id: "%s"
				jwt: "%s"
			}
		) {
			numUids
		}
	}`

	mu = fmt.Sprintf(mu, id, jwt)

	var response struct {
		Response struct {
			NumUIDs int `json:"numUids"`
		} `json:"addToken"`
	}
	_, err := db.client.Do(ctx, &graphql.Request{
		Query:    mu,
		Response: &response,
	})
	if err != nil {
		return err
	}
	if response.Response.NumUIDs == 0 {
		return errors.New("error saving token")
	}

	return nil
}

// IsTokenSeen returns an error if the token has been seen before. If not, it first
// records the token information so that subsequent calls return true.
func (db *DgraphDatabase) IsTokenSeen(ctx context.Context, token *jwt.Token) (bool, error) {
	_, err := db.GetTokenByID(ctx, token.Claims.JwtID)
	if err != nil {
		if err != ErrNotFound {
			return false, err
		}

		return false, db.RegisterToken(ctx, token)
	}
	return true, nil
}

// GetTokenByID looks up and returns the encoded token corresponding to the provided ID.
func (db *DgraphDatabase) GetTokenByID(ctx context.Context, tokenID string) (string, error) {
	q := `
	query {
		getToken(id: "%s") {
			id
			jwt
		}
	}
	`

	q = fmt.Sprintf(q, tokenID)

	var response struct {
		Token struct {
			ID  string `json:"id"`
			JWT string `json:"jwt"`
		} `json:"getToken"`
	}
	_, err := db.client.Do(ctx, &graphql.Request{
		Query:    q,
		Response: &response,
	})
	if err != nil {
		return "", err
	}
	if response.Token.ID != tokenID || response.Token.JWT == "" {
		return "", ErrNotFound
	}

	return response.Token.JWT, nil
}

// RegisterUser registers a new user in the authentication database.
func (db *DgraphDatabase) RegisterUser(ctx context.Context, user *model.User) error {
	mu := `
	mutation {
		addUser(
			input: %s
		) {
			numUids
		}
	}
	`

	mu = fmt.Sprintf(mu, user.GQL())

	var response struct {
		Response struct {
			NumUIDs int `json:"numUids"`
		} `json:"addUser"`
	}
	_, err := db.client.Do(ctx, &graphql.Request{
		Query:    mu,
		Response: &response,
	})
	if err != nil {
		return err
	}
	if response.Response.NumUIDs == 0 {
		return errors.New("error saving user")
	}

	return nil
}

// GetUserByID retrieves user's info based off a user's ID.
func (db *DgraphDatabase) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	q := `
	%s
	query {
		getUser(id: "%s") {
			...AllUserInfo
		}
	}
	`

	q = fmt.Sprintf(q, model.AllUserInfo, id)

	var response struct {
		User model.User `json:"getUser"`
	}
	_, err := db.client.Do(ctx, &graphql.Request{
		Query:    q,
		Response: &response,
	})
	if err != nil {
		return nil, err
	}
	if response.User.ID != id {
		return nil, ErrNotFound
	}

	return &response.User, nil
}

// GetUserByUsername retrieves user's info based off a username.
func (db *DgraphDatabase) GetUserByUsername(ctx context.Context, username, clientID string) (*model.User, error) {
	q := `
	%s
	query {
		queryUser(
			filter: {
				username: {eq: "%s"}
				client_id: {eq: "%s"}
			}
		) {
			...AllUserInfo
		}
	}
	`

	q = fmt.Sprintf(q, model.AllUserInfo, username, clientID)

	var response struct {
		Users []*model.User `json:"queryUser"`
	}
	_, err := db.client.Do(ctx, &graphql.Request{
		Query:    q,
		Response: &response,
	})
	if err != nil {
		return nil, err
	}
	if len(response.Users) == 0 {
		return nil, ErrNotFound
	}

	return response.Users[0], nil
}

// VerifyUsernameAndPassword returns an error if the username and password combo do not match what's in the DB.
func (db *DgraphDatabase) VerifyUsernameAndPassword(ctx context.Context, username, clientID, password string) (*model.User, error) {
	user, err := db.GetUserByUsername(ctx, username, clientID)
	if err != nil {
		return nil, err
	}
	if !passwordutil.CheckPasswordHash(password, user.PasswordHash) {
		return nil, errors.New("invalid password")
	}
	return user, nil
}

var _ Database = (*DgraphDatabase)(nil)
