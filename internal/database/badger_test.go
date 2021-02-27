package database

import (
	"context"
	"reflect"
	"testing"

	"github.com/dgraph-io/badger/v3"
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

func TestCreateAdmin(t *testing.T) {
	config.LoadConfig()

	db, err := InitializeBadgerDB(BadgerOptions{InMemory: true, SeedDB: true})
	defer db.Close()
	require.NoError(t, err)

	admin := db.AdminClient

	client, err := db.GetClient(context.Background(), admin.ID)
	require.NoError(t, err)

	assert.True(t, reflect.DeepEqual(client, admin))
}

func TestRegisterClient(t *testing.T) {
	config.LoadConfig()

	db, err := InitializeBadgerDB(BadgerOptions{InMemory: true})
	defer db.Close()

	require.NoError(t, err)

	_, err = db.RegisterClient(
		context.Background(),
		&mock.PublicClient,
		model.ClientOptionNone,
	)
	require.NoError(t, err)

	client, err := db.GetClient(context.Background(), mock.PublicClient.ID)
	require.NoError(t, err)
	assert.True(t, reflect.DeepEqual(client, &mock.PublicClient))
}

func TestGetClient(t *testing.T) {
	ctx := context.Background()

	config.LoadConfig()

	db, err := InitializeBadgerDB(BadgerOptions{InMemory: true, SeedDB: true})
	defer db.Close()
	require.NoError(t, err)

	admin := db.AdminClient

	client, err := db.GetClient(ctx, admin.ID)
	require.NoError(t, err)
	assert.True(t, reflect.DeepEqual(client, admin))
}

func TestUpdateClient(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	db, err := InitializeBadgerDB(BadgerOptions{InMemory: true})
	defer db.Close()
	require.NoError(t, err)

	_, err = db.RegisterClient(ctx, &mock.PublicClient, model.ClientOptionNone)
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

func TestGetAdminClient(t *testing.T) {
	config.LoadConfig()

	db, err := InitializeBadgerDB(BadgerOptions{InMemory: true, SeedDB: true})
	defer db.Close()
	require.NoError(t, err)

	admin := db.AdminClient

	loadedClient, err := db.getAdminClient()
	require.NoError(t, err)

	assert.True(t, reflect.DeepEqual(admin, loadedClient))
}

func TestListClients(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	db, err := InitializeBadgerDB(BadgerOptions{InMemory: true, SeedDB: true})
	defer db.Close()
	require.NoError(t, err)

	admin := db.AdminClient

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

func TestDeleteClient(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	db, err := InitializeBadgerDB(BadgerOptions{InMemory: true})
	defer db.Close()
	require.NoError(t, err)

	_, err = db.RegisterClient(ctx, &mock.PublicClient, model.ClientOptionNone)
	require.NoError(t, err)

	client, err := db.GetClient(ctx, mock.PublicClient.ID)
	require.NoError(t, err)
	require.True(t, reflect.DeepEqual(client, &mock.PublicClient))

	err = db.DeleteClient(ctx, mock.PublicClient.ID)
	require.NoError(t, err)

	_, err = db.GetClient(ctx, mock.PublicClient.ID)
	assert.Equal(t, badger.ErrKeyNotFound, err)
}

func TestCreateSession(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	db, err := InitializeBadgerDB(BadgerOptions{InMemory: true, SeedDB: true})
	defer db.Close()
	require.NoError(t, err)

	admin := db.AdminClient

	id, err := uuid.NewV4()
	require.NoError(t, err)

	req := &model.AuthorizationRequest{
		ID:                  id.String(),
		GrantType:           string(model.GrantTypeAuthorizationCode),
		ClientID:            admin.ID,
		Scope:               "default",
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

func TestGetRequestInfo(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	db, err := InitializeBadgerDB(BadgerOptions{InMemory: true, SeedDB: true})
	defer db.Close()
	require.NoError(t, err)

	admin := db.AdminClient

	id, err := uuid.NewV4()
	require.NoError(t, err)

	req := &model.AuthorizationRequest{
		ID:                  id.String(),
		GrantType:           string(model.GrantTypeAuthorizationCode),
		ClientID:            admin.ID,
		Scope:               "default",
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

func TestUpdateRequestInfo(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	db, err := InitializeBadgerDB(BadgerOptions{InMemory: true, SeedDB: true})
	defer db.Close()
	require.NoError(t, err)

	admin := db.AdminClient

	id, err := uuid.NewV4()
	require.NoError(t, err)

	req := &model.AuthorizationRequest{
		ID:                  id.String(),
		GrantType:           string(model.GrantTypeAuthorizationCode),
		ClientID:            admin.ID,
		Scope:               "default",
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

	assert.True(t, reflect.DeepEqual(req, session))
}

func TestLookupSessionByCode(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	db, err := InitializeBadgerDB(BadgerOptions{InMemory: true, SeedDB: true})
	defer db.Close()
	require.NoError(t, err)

	admin := db.AdminClient

	id, err := uuid.NewV4()
	require.NoError(t, err)

	req1 := model.AuthorizationRequest{
		ID:                  id.String(),
		GrantType:           string(model.GrantTypeAuthorizationCode),
		ClientID:            admin.ID,
		Scope:               "default",
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
	assert.True(t, reflect.DeepEqual(&req1, session))
}

func TestRegisterTokens(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	db, err := InitializeBadgerDB(BadgerOptions{InMemory: true, SeedDB: true})
	defer db.Close()
	require.NoError(t, err)

	admin := db.AdminClient

	accessToken, err := token.IssueAccessToken(admin, &model.User{ID: "test"}, "default")
	require.NoError(t, err)

	refreshToken, err := token.IssueRefreshToken(admin, accessToken)
	require.NoError(t, err)

	t.Run("Commit", func(t *testing.T) {
		commit, _, err := db.RegisterTokens(ctx, accessToken, refreshToken)
		require.NoError(t, err)
		err = commit()
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
	})

	db.Reset()

	t.Run("Rollback", func(t *testing.T) {
		_, rollback, err := db.RegisterTokens(ctx, accessToken, refreshToken)
		require.NoError(t, err)
		err = rollback()
		require.NoError(t, err)

		_, err = db.GetTokenByID(ctx, accessToken.Claims.JwtID)
		require.Equal(t, err, badger.ErrKeyNotFound)

		_, err = db.GetTokenByID(ctx, refreshToken.Claims.JwtID)
		require.Equal(t, err, badger.ErrKeyNotFound)
	})
}

func TestGetTokenByID(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	db, err := InitializeBadgerDB(BadgerOptions{InMemory: true, SeedDB: true})
	defer db.Close()
	require.NoError(t, err)

	admin := db.AdminClient

	accessToken, err := token.IssueAccessToken(admin, &model.User{ID: "test"}, "default")
	require.NoError(t, err)

	refreshToken, err := token.IssueRefreshToken(admin, accessToken)
	require.NoError(t, err)

	commit, _, err := db.RegisterTokens(ctx, accessToken, refreshToken)
	require.NoError(t, err)
	err = commit()
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

func TestIsTokenSeen(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	db, err := InitializeBadgerDB(BadgerOptions{InMemory: true, SeedDB: true})
	defer db.Close()
	require.NoError(t, err)

	admin := db.AdminClient

	token, err := token.IssueAccessToken(admin, &model.User{ID: "test"}, "default")
	require.NoError(t, err)

	err = db.IsTokenSeen(ctx, token)
	require.NoError(t, err)

	err = db.IsTokenSeen(ctx, token)
	require.Error(t, err)
}

func TestCreateUser(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	db, err := InitializeBadgerDB(BadgerOptions{InMemory: true})
	defer db.Close()
	require.NoError(t, err)

	passwordHash, err := passwordutil.GeneratePasswordHash("password")
	require.NoError(t, err)

	user := &model.User{ID: "test", Username: "username", PasswordHash: passwordHash}
	err = db.CreateUser(ctx, user.ID, user.Username, user.PasswordHash)
	assert.NoError(t, err)
}

func TestGetUserByID(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	db, err := InitializeBadgerDB(BadgerOptions{InMemory: true})
	defer db.Close()
	require.NoError(t, err)

	passwordHash, err := passwordutil.GeneratePasswordHash("password")
	require.NoError(t, err)

	user := &model.User{ID: "test", Username: "username", PasswordHash: passwordHash}
	err = db.CreateUser(ctx, user.ID, user.Username, user.PasswordHash)
	require.NoError(t, err)

	retrievedUser, err := db.GetUserByID(ctx, user.ID)
	require.NoError(t, err)
	assert.True(t, reflect.DeepEqual(retrievedUser, user))

	_, err = db.GetUserByID(ctx, "random_id")
	assert.Error(t, err)
	assert.Equal(t, badger.ErrKeyNotFound, err)
}

func TestGetUserByUsername(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	db, err := InitializeBadgerDB(BadgerOptions{InMemory: true})
	defer db.Close()
	require.NoError(t, err)

	passwordHash, err := passwordutil.GeneratePasswordHash("password")
	require.NoError(t, err)

	user := &model.User{ID: "test", Username: "username", PasswordHash: passwordHash}
	err = db.CreateUser(ctx, user.ID, user.Username, user.PasswordHash)
	require.NoError(t, err)

	retrievedUser, err := db.GetUserByUsername(ctx, user.Username)
	require.NoError(t, err)
	assert.True(t, reflect.DeepEqual(retrievedUser, user))

	_, err = db.GetUserByUsername(ctx, "random_username")
	assert.Error(t, err)
	assert.Equal(t, badger.ErrKeyNotFound, err)
}

func TestVerifyUsernameAndPassword(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	db, err := InitializeBadgerDB(BadgerOptions{InMemory: true})
	defer db.Close()
	require.NoError(t, err)

	passwordHash, err := passwordutil.GeneratePasswordHash("password")
	require.NoError(t, err)

	user := &model.User{ID: "test", Username: "username", PasswordHash: passwordHash}
	err = db.CreateUser(ctx, user.ID, user.Username, user.PasswordHash)
	assert.NoError(t, err)

	err = db.VerifyUsernameAndPassword(ctx, "username", "password")
	assert.NoError(t, err)

	err = db.VerifyUsernameAndPassword(ctx, "username", "wrong_password")
	assert.Error(t, err)

	err = db.VerifyUsernameAndPassword(ctx, "wrong_username", "password")
	assert.Error(t, err)
}
