package database

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"testing"

	badger "github.com/dgraph-io/badger/v3"
	"github.com/ftauth/ftauth/internal/config"
	"github.com/ftauth/ftauth/internal/mock"
	"github.com/ftauth/ftauth/internal/token"
	"github.com/ftauth/ftauth/pkg/jwt"
	"github.com/ftauth/ftauth/pkg/model"
	"github.com/ftauth/ftauth/pkg/util/passwordutil"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	badgerClient      *BadgerDB
	dgraphClient      *DgraphDatabase
	dgraphSlashClient *DgraphDatabase

	dgraphGraphQLUrl = os.Getenv("DGRAPH_URL")
	dgraphGrpcUrl    = os.Getenv("DGRAPH_GRPC")
	dgraphApiKey     = os.Getenv("DGRAPH_API_KEY")

	dgraphSlashGraphQlUrl = os.Getenv("DGRAPH_SLASH_URL")
	dgraphSlashGrpcUrl    = os.Getenv("DGRAPH_SLASH_GRPC")
	dgraphSlashApiKey     = os.Getenv("DGRAPH_SLASH_API_KEY")
)

func runDgraph() bool {
	return dgraphGraphQLUrl != "" && dgraphGrpcUrl != ""
}

func runDgraphSlash() bool {
	return dgraphSlashGraphQlUrl != "" && dgraphSlashGrpcUrl != "" && dgraphSlashApiKey != ""
}

func requireNotFound(t *testing.T, err error) {
	require.True(t, err == badger.ErrKeyNotFound || err == ErrNotFound)
}

func setupDgraph(t *testing.T) {
	if dgraphClient == nil {
		var err error
		dgraphClient, err = NewDgraphDatabase(context.Background(), &config.DatabaseConfig{
			URL:     dgraphGraphQLUrl,
			Grpc:    dgraphGrpcUrl,
			APIKey:  dgraphApiKey,
			SeedDB:  true,
			DropAll: true,
		})
		require.NoError(t, err)
	} else {
		_, err := CreateAdminClient(context.Background(), dgraphClient)
		require.NoError(t, err)
	}
}

func setupDgraphSlash(t *testing.T) {
	if dgraphSlashClient == nil {
		var err error
		dgraphSlashClient, err = NewDgraphDatabase(context.Background(), &config.DatabaseConfig{
			URL:     dgraphSlashGraphQlUrl,
			Grpc:    dgraphSlashGrpcUrl,
			APIKey:  dgraphSlashApiKey,
			SeedDB:  true,
			DropAll: true,
		})
		require.NoError(t, err)
	} else {
		_, err := CreateAdminClient(context.Background(), dgraphSlashClient)
		require.NoError(t, err)
	}
}

func teardownDgraph(t *testing.T) {
	ctx := context.Background()
	err := dgraphClient.DropAll(ctx)
	require.NoError(t, err)
}

func teardownDgraphSlash(t *testing.T) {
	ctx := context.Background()
	err := dgraphSlashClient.DropAll(ctx)
	require.NoError(t, err)
}

func setupBadger(t *testing.T) {
	if badgerClient == nil {
		var err error
		badgerClient, err = NewBadgerDB(true, &config.DatabaseConfig{
			SeedDB:  true,
			DropAll: true,
		})
		require.NoError(t, err)
	} else {
		_, err := CreateAdminClient(context.Background(), badgerClient)
		require.NoError(t, err)
	}
}

func teardownBadger(t *testing.T) {
	err := badgerClient.Close()
	require.NoError(t, err)
	badgerClient = nil
}

func runTest(t *testing.T, test func(Database)) {
	t.Run("Badger", func(t *testing.T) {
		setupBadger(t)
		test(badgerClient)
		teardownBadger(t)
	})

	if runDgraph() {
		t.Run("Dgraph", func(t *testing.T) {
			setupDgraph(t)
			test(dgraphClient)
			teardownDgraph(t)
		})
	}

	if runDgraphSlash() {
		t.Run("Dgraph Slash", func(t *testing.T) {
			setupDgraphSlash(t)
			test(dgraphSlashClient)
			teardownDgraphSlash(t)
		})
	}
}

func TestDropAll(t *testing.T) {
	config.LoadConfig()
	ctx := context.Background()

	test := func(db Database) {
		admin, err := db.GetDefaultAdminClient(ctx)
		require.NoError(t, err)
		require.NotNil(t, admin)

		err = db.DropAll(ctx)
		require.NoError(t, err)

		admin, err = db.GetDefaultAdminClient(ctx)
		require.Nil(t, admin)
		require.Equal(t, ErrNotFound, err)
	}

	runTest(t, test)
}

func TestCreateAdmin(t *testing.T) {
	config.LoadConfig()
	ctx := context.Background()

	test := func(db Database) {
		admin, err := db.GetDefaultAdminClient(ctx)
		require.NoError(t, err)

		client, err := db.GetClient(ctx, admin.ID)
		require.NoError(t, err)

		assert.True(t, reflect.DeepEqual(client, admin))
	}

	runTest(t, test)
}

func TestRegisterClient(t *testing.T) {
	config.LoadConfig()
	ctx := context.Background()

	test := func(db Database) {
		_, err := db.RegisterClient(
			ctx,
			&mock.PublicClient,
			model.ClientOptionNone,
		)
		require.NoError(t, err)

		client, err := db.GetClient(ctx, mock.PublicClient.ID)
		require.NoError(t, err)
		assert.True(t, reflect.DeepEqual(client, &mock.PublicClient))
	}

	runTest(t, test)
}

func TestGetClient(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	test := func(db Database) {
		admin, err := db.GetDefaultAdminClient(ctx)
		require.NoError(t, err)
		client, err := db.GetClient(ctx, admin.ID)
		require.NoError(t, err)
		assert.True(t, reflect.DeepEqual(client, admin))
	}

	runTest(t, test)
}

func TestUpdateClient(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	test := func(db Database) {
		_, err := db.RegisterClient(ctx, &mock.PublicClient, model.ClientOptionNone)
		require.NoError(t, err)

		id := mock.PublicClient.ID
		name := "Updated Client"
		redirectUrls := []string{"localhost", "myapp://auth"}
		scopes := []*model.Scope{
			{Name: "default"},
			{Name: "new_scope"},
		}
		jwksURI := "https://example.com/jwks.json"
		logoURI := "https://example.com/logo.png"
		accessTokenLife := 60 * 60 * 3
		refreshTokenLife := 60 * 60 * 24 * 2
		clientUpdate := model.ClientInfoUpdate{
			ID:               id,
			Name:             &name,
			RedirectURIs:     &redirectUrls,
			Scopes:           &scopes,
			JWKsURI:          &jwksURI,
			LogoURI:          &logoURI,
			AccessTokenLife:  &accessTokenLife,
			RefreshTokenLife: &refreshTokenLife,
		}

		updatedClient, err := db.UpdateClient(ctx, clientUpdate)
		require.NoError(t, err)

		// Assert the correct values were changed
		assert.Equal(t, mock.PublicClient.ID, updatedClient.ID)
		assert.Equal(t, mock.PublicClient.Type, updatedClient.Type)
		assert.Equal(t, mock.PublicClient.Secret, updatedClient.Secret)
		assert.Equal(t, mock.PublicClient.SecretExpiry, updatedClient.SecretExpiry)
		assert.Equal(t, mock.PublicClient.GrantTypes, updatedClient.GrantTypes)
		assert.NotEqual(t, mock.PublicClient.Name, updatedClient.Name)
		assert.NotEqual(t, mock.PublicClient.RedirectURIs, updatedClient.Name)
		assert.NotEqual(t, mock.PublicClient.Scopes, updatedClient.Scopes)
		assert.NotEqual(t, mock.PublicClient.JWKsURI, updatedClient.JWKsURI)
		assert.NotEqual(t, mock.PublicClient.LogoURI, updatedClient.LogoURI)
		assert.NotEqual(t, mock.PublicClient.AccessTokenLife, updatedClient.AccessTokenLife)
		assert.NotEqual(t, mock.PublicClient.RefreshTokenLife, updatedClient.RefreshTokenLife)

		// Assert the values were updated appropriately
		assert.Equal(t, name, updatedClient.Name)
		assert.Equal(t, redirectUrls, updatedClient.RedirectURIs)
		assert.Equal(t, scopes, updatedClient.Scopes)
		assert.Equal(t, jwksURI, updatedClient.JWKsURI)
		assert.Equal(t, logoURI, updatedClient.LogoURI)
		assert.Equal(t, accessTokenLife, updatedClient.AccessTokenLife)
		assert.Equal(t, refreshTokenLife, updatedClient.RefreshTokenLife)
	}

	runTest(t, test)
}

func TestGetAdminClient(t *testing.T) {
	config.LoadConfig()
	ctx := context.Background()

	test := func(db Database) {
		admin, err := db.GetDefaultAdminClient(ctx)
		require.NoError(t, err)
		require.NotNil(t, admin)
	}

	runTest(t, test)
}

func TestListClients(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	test := func(db Database) {
		admin, err := db.GetDefaultAdminClient(ctx)
		require.NoError(t, err)

		_, err = db.RegisterClient(ctx, &mock.PublicClient, model.ClientOptionNone)
		require.NoError(t, err)

		_, err = db.RegisterClient(ctx, &mock.ConfidentialClient, model.ClientOptionNone)
		require.NoError(t, err)

		clients, err := db.ListClients(ctx)
		require.NoError(t, err)

		assert.Len(t, clients, 3)
		for _, client := range clients {
			assert.True(t, reflect.DeepEqual(client, admin) ||
				reflect.DeepEqual(client, &mock.PublicClient) ||
				reflect.DeepEqual(client, &mock.ConfidentialClient))
		}
	}

	runTest(t, test)
}

func TestDeleteClient(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	test := func(db Database) {
		_, err := db.RegisterClient(ctx, &mock.PublicClient, model.ClientOptionNone)
		require.NoError(t, err)

		client, err := db.GetClient(ctx, mock.PublicClient.ID)
		require.NoError(t, err)
		require.True(t, reflect.DeepEqual(client, &mock.PublicClient))

		err = db.DeleteClient(ctx, mock.PublicClient.ID)
		require.NoError(t, err)

		_, err = db.GetClient(ctx, mock.PublicClient.ID)
		requireNotFound(t, err)
	}

	runTest(t, test)
}

func TestCreateSession(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	test := func(db Database) {
		admin, err := db.GetDefaultAdminClient(ctx)
		require.NoError(t, err)

		id, err := uuid.NewV4()
		require.NoError(t, err)

		req := &model.AuthorizationRequest{
			ID:                  id.String(),
			ClientID:            admin.ID,
			Scope:               []*model.Scope{{Name: "default"}},
			State:               "state",
			RedirectURI:         "http://localhost:8080/auth",
			Code:                "code",
			CodeChallenge:       "code_challenge",
			CodeChallengeMethod: model.CodeChallengeMethodPlain,
			UserID:              "test",
		}
		err = db.CreateSession(ctx, req)
		assert.NoError(t, err)
	}

	runTest(t, test)
}

func TestGetRequestInfo(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	test := func(db Database) {
		admin, err := db.GetDefaultAdminClient(ctx)
		require.NoError(t, err)

		id, err := uuid.NewV4()
		require.NoError(t, err)

		req := &model.AuthorizationRequest{
			ID:                  id.String(),
			ClientID:            admin.ID,
			Scope:               []*model.Scope{{Name: "default"}},
			State:               "state",
			RedirectURI:         "http://localhost:8080/auth",
			Code:                "code",
			CodeChallenge:       "code_challenge",
			CodeChallengeMethod: model.CodeChallengeMethodPlain,
			UserID:              "test",
		}
		err = db.CreateSession(ctx, req)
		require.NoError(t, err)

		session, err := db.GetRequestInfo(ctx, id.String())
		require.NoError(t, err)

		assert.True(t, reflect.DeepEqual(req, session))
	}

	runTest(t, test)
}

func TestUpdateRequestInfo(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	test := func(db Database) {
		admin, err := db.GetDefaultAdminClient(ctx)
		require.NoError(t, err)

		id, err := uuid.NewV4()
		require.NoError(t, err)

		req := &model.AuthorizationRequest{
			ID:                  id.String(),
			ClientID:            admin.ID,
			Scope:               []*model.Scope{{Name: "default"}},
			State:               "state",
			RedirectURI:         "http://localhost:8080/auth",
			Code:                "code",
			CodeChallenge:       "code_challenge",
			CodeChallengeMethod: model.CodeChallengeMethodPlain,
		}
		err = db.CreateSession(ctx, req)
		require.NoError(t, err)

		session, err := db.GetRequestInfo(ctx, id.String())
		require.NoError(t, err)

		require.True(t, reflect.DeepEqual(req, session))

		req.UserID = "test"

		err = db.UpdateRequestInfo(ctx, req)
		require.NoError(t, err)

		session, err = db.GetRequestInfo(ctx, id.String())
		require.NoError(t, err)

		require.True(t, reflect.DeepEqual(req, session))
	}

	runTest(t, test)
}

func TestLookupSessionByCode(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	test := func(db Database) {
		admin, err := db.GetDefaultAdminClient(ctx)
		require.NoError(t, err)

		id, err := uuid.NewV4()
		require.NoError(t, err)

		req1 := model.AuthorizationRequest{
			ID:                  id.String(),
			ClientID:            admin.ID,
			Scope:               []*model.Scope{{Name: "default"}},
			State:               "state",
			RedirectURI:         "http://localhost:8080/auth",
			Code:                "code",
			CodeChallenge:       "code_challenge",
			CodeChallengeMethod: model.CodeChallengeMethodPlain,
			UserID:              "test",
		}
		err = db.CreateSession(ctx, &req1)
		require.NoError(t, err)

		id2, err := uuid.NewV4()
		require.NoError(t, err)

		// Create second request
		req2 := req1
		req2.ID = id2.String()
		req2.Code = "another_code"

		err = db.CreateSession(ctx, &req2)
		require.NoError(t, err)

		// Create third request
		id3, err := uuid.NewV4()
		require.NoError(t, err)

		req3 := req1
		req3.ID = id3.String()
		req3.Code = "third_code"

		err = db.CreateSession(ctx, &req3)
		require.NoError(t, err)

		// Ensure retrieved request matches the first one
		session, err := db.LookupSessionByCode(ctx, "code")
		require.NoError(t, err)
		require.True(t, reflect.DeepEqual(&req1, session))
	}

	runTest(t, test)
}

func TestRegisterTokens(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	test := func(db Database) {
		admin, err := db.GetDefaultAdminClient(ctx)
		require.NoError(t, err)

		accessToken, err := token.IssueAccessToken(admin, &model.User{ID: "test"}, "default")
		require.NoError(t, err)

		refreshToken, err := token.IssueRefreshToken(admin, accessToken)
		require.NoError(t, err)

		err = db.RegisterToken(ctx, accessToken)
		require.NoError(t, err)
		err = db.RegisterToken(ctx, refreshToken)
		require.NoError(t, err)

		accessTokenJwt, err := db.GetTokenByID(ctx, accessToken.Claims.JwtID)
		require.NoError(t, err)

		retrievedAccessToken, err := jwt.Decode(accessTokenJwt)
		require.NoError(t, err)

		accessRaw, err := accessToken.Raw()
		require.NoError(t, err)

		retrievedRaw, err := retrievedAccessToken.Raw()
		require.NoError(t, err)

		assert.Equal(t, accessRaw, retrievedRaw)

		refreshTokenJwt, err := db.GetTokenByID(ctx, refreshToken.Claims.JwtID)
		require.NoError(t, err)

		retrievedRefreshToken, err := jwt.Decode(refreshTokenJwt)
		require.NoError(t, err)

		refreshRaw, err := refreshToken.Raw()
		require.NoError(t, err)

		retrievedRefreshRaw, err := retrievedRefreshToken.Raw()
		require.NoError(t, err)

		assert.Equal(t, refreshRaw, retrievedRefreshRaw)
	}

	runTest(t, test)
}

func TestGetTokenByID(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	test := func(db Database) {
		admin, err := db.GetDefaultAdminClient(ctx)
		require.NoError(t, err)

		accessToken, err := token.IssueAccessToken(admin, &model.User{ID: "test"}, "default")
		require.NoError(t, err)

		refreshToken, err := token.IssueRefreshToken(admin, accessToken)
		require.NoError(t, err)

		err = db.RegisterToken(ctx, accessToken)
		require.NoError(t, err)
		err = db.RegisterToken(ctx, refreshToken)
		require.NoError(t, err)

		accessTokenJwt, err := db.GetTokenByID(ctx, accessToken.Claims.JwtID)
		require.NoError(t, err)

		retrievedAccessToken, err := jwt.Decode(accessTokenJwt)
		require.NoError(t, err)

		accessRaw, err := accessToken.Raw()
		require.NoError(t, err)

		retrievedRaw, err := retrievedAccessToken.Raw()
		require.NoError(t, err)

		assert.Equal(t, accessRaw, retrievedRaw)

		refreshTokenJwt, err := db.GetTokenByID(ctx, refreshToken.Claims.JwtID)
		require.NoError(t, err)

		retrievedRefreshToken, err := jwt.Decode(refreshTokenJwt)
		require.NoError(t, err)

		refreshRaw, err := refreshToken.Raw()
		require.NoError(t, err)

		retrievedRefreshRaw, err := retrievedRefreshToken.Raw()
		require.NoError(t, err)

		assert.Equal(t, refreshRaw, retrievedRefreshRaw)
	}

	runTest(t, test)
}

func TestIsTokenSeen(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	test := func(db Database) {
		admin, err := db.GetDefaultAdminClient(ctx)
		require.NoError(t, err)

		token, err := token.IssueAccessToken(admin, &model.User{ID: "test"}, "default")
		require.NoError(t, err)

		seen, err := db.IsTokenSeen(ctx, token)
		require.NoError(t, err)
		require.False(t, seen)

		seen, err = db.IsTokenSeen(ctx, token)
		require.NoError(t, err)
		require.True(t, seen)
	}

	runTest(t, test)
}

func TestRegisterUser(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	test := func(db Database) {
		passwordHash, err := passwordutil.GeneratePasswordHash("password")
		require.NoError(t, err)

		user := &model.User{ID: "test", Username: "username", PasswordHash: passwordHash}
		err = db.RegisterUser(ctx, user)
		assert.NoError(t, err)
	}

	runTest(t, test)
}

func TestGetUserByID(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	test := func(db Database) {
		passwordHash, err := passwordutil.GeneratePasswordHash("password")
		require.NoError(t, err)

		user := &model.User{ID: "test", Username: "username", PasswordHash: passwordHash}
		err = db.RegisterUser(ctx, user)
		require.NoError(t, err)

		retrievedUser, err := db.GetUserByID(ctx, user.ID)
		require.NoError(t, err)
		require.Equal(t, user.ID, retrievedUser.ID)
		require.Equal(t, user.Username, retrievedUser.Username)
		require.Equal(t, user.PasswordHash, retrievedUser.PasswordHash)

		_, err = db.GetUserByID(ctx, "random_id")
		require.Error(t, err)
		requireNotFound(t, err)
	}

	runTest(t, test)
}

func TestGetUserByUsername(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	test := func(db Database) {
		passwordHash, err := passwordutil.GeneratePasswordHash("password")
		require.NoError(t, err)

		user := &model.User{ID: "test", ClientID: "client", Username: "username", PasswordHash: passwordHash}
		err = db.RegisterUser(ctx, user)
		require.NoError(t, err)

		retrievedUser, err := db.GetUserByUsername(ctx, user.Username, "client")
		require.NoError(t, err)
		require.Equal(t, user.ID, retrievedUser.ID)
		require.Equal(t, user.ClientID, retrievedUser.ClientID)
		require.Equal(t, user.Username, retrievedUser.Username)
		require.Equal(t, user.PasswordHash, retrievedUser.PasswordHash)

		_, err = db.GetUserByUsername(ctx, "random_username", "client")
		require.Error(t, err)
		requireNotFound(t, err)
	}

	runTest(t, test)
}

func TestVerifyUsernameAndPassword(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	test := func(db Database) {
		passwordHash, err := passwordutil.GeneratePasswordHash("password")
		require.NoError(t, err)

		user := &model.User{ID: "test", ClientID: "client", Username: "username", PasswordHash: passwordHash}
		err = db.RegisterUser(ctx, user)
		require.NoError(t, err)

		retrievedUser, err := db.VerifyUsernameAndPassword(ctx, "username", "client", "password")
		require.NoError(t, err)
		require.Equal(t, user.ID, retrievedUser.ID)
		require.Equal(t, user.ClientID, retrievedUser.ClientID)
		require.Equal(t, user.Username, retrievedUser.Username)
		require.Equal(t, user.PasswordHash, retrievedUser.PasswordHash)

		_, err = db.VerifyUsernameAndPassword(ctx, "username", "client", "wrong_password")
		require.Error(t, err)

		_, err = db.VerifyUsernameAndPassword(ctx, "wrong_username", "client", "password")
		require.Error(t, err)
	}

	runTest(t, test)
}

func TestRegisterScope(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	test := func(db Database) {
		scopeName := fmt.Sprintf("my_scope_%d", rand.Int())

		scope, err := db.RegisterScope(ctx, scopeName)
		require.NoError(t, err)
		require.Equal(t, scopeName, scope.Name)
	}

	runTest(t, test)
}

func TestGetScope(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	test := func(db Database) {
		const scopeName = "my_scope"

		scope, err := db.RegisterScope(ctx, scopeName)
		require.NoError(t, err)
		require.Equal(t, scopeName, scope.Name)

		scope, err = db.GetScope(ctx, scopeName)
		require.NoError(t, err)
		require.Equal(t, scopeName, scope.Name)
	}

	runTest(t, test)
}

func TestDeleteScope(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	test := func(db Database) {
		const scopeName = "my_scope"

		scope, err := db.RegisterScope(ctx, scopeName)
		require.NoError(t, err)
		require.Equal(t, scopeName, scope.Name)

		scope, err = db.GetScope(ctx, scopeName)
		require.NoError(t, err)
		require.Equal(t, scopeName, scope.Name)

		err = db.DeleteScope(ctx, scopeName)
		require.NoError(t, err)

		_, err = db.GetScope(ctx, scopeName)
		require.EqualError(t, err, "Key not found")
	}

	runTest(t, test)
}

func TestListScopes(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	test := func(db Database) {
		scopeNames := []string{"scope1", "scope2", "scope3"}

		for _, scopeName := range scopeNames {
			scope, err := db.RegisterScope(ctx, scopeName)
			require.NoError(t, err)
			require.Equal(t, scopeName, scope.Name)
		}

		scopes, err := db.ListScopes(ctx)
		require.NoError(t, err)
		for _, scopeName := range scopeNames {
			var found bool
			for _, scope := range scopes {
				if scope.Name == scopeName {
					found = true
					break
				}
			}
			require.True(t, found)
		}

	}

	runTest(t, test)
}
