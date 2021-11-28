package database

import (
	"context"
	"fmt"
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

var _runDgraph *bool

func runDgraph() bool {
	if dgraphClient != nil {
		return true
	}
	if _runDgraph == nil {
		var err error
		dgraphClient, err = NewDgraphDatabase(context.Background())
		_runDgraph = new(bool)
		*_runDgraph = err == nil
		if err != nil {
			fmt.Println("Not running Dgraph tests due to error: ", err)
		}
	}
	return *_runDgraph
}

func requireNotFound(t *testing.T, err error) {
	require.True(t, err == badger.ErrKeyNotFound || err == ErrNotFound)
}

var dgraphClient *DgraphDatabase

func setupDgraph(t *testing.T) {
	if dgraphClient != nil {
		_, err := CreateAdminClient(context.Background(), dgraphClient)
		require.NoError(t, err)
	}
}

func teardownDgraph(t *testing.T) {
	ctx := context.Background()
	err := dgraphClient.DropAll(ctx)
	require.NoError(t, err)
}

var badgerClient *BadgerDB

func setupBadger(t *testing.T) {
	if badgerClient == nil {
		db, err := NewBadgerDB(true)
		require.NoError(t, err)
		badgerClient = db
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
}

func TestGetAdminClient(t *testing.T) {
	config.LoadConfig()
	ctx := context.Background()

	test := func(db Database) {
		admin, err := db.GetDefaultAdminClient(ctx)
		require.NoError(t, err)
		require.NotNil(t, admin)
	}

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
}
