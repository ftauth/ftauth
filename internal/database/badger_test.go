package database

import (
	"context"
	"reflect"
	"testing"

	"github.com/dgraph-io/badger/v3"
	"github.com/ftauth/ftauth/internal/config"
	"github.com/ftauth/ftauth/internal/mock"
	"github.com/ftauth/ftauth/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateAdmin(t *testing.T) {
	config.LoadConfig()

	db, admin, err := InitializeBadgerDB(true)
	defer db.Close()

	require.NoError(t, err)

	client, err := db.GetClient(context.Background(), admin.ID)
	require.NoError(t, err)

	assert.True(t, reflect.DeepEqual(client, admin))
}

func TestRegisterClient(t *testing.T) {
	config.LoadConfig()

	db, _, err := InitializeBadgerDB(true)
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

	db, admin, err := InitializeBadgerDB(true)
	defer db.Close()
	require.NoError(t, err)

	client, err := db.GetClient(ctx, admin.ID)
	require.NoError(t, err)
	assert.True(t, reflect.DeepEqual(client, admin))
}

func TestUpdateClient(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	db, _, err := InitializeBadgerDB(true)
	defer db.Close()
	require.NoError(t, err)

	_, err = db.RegisterClient(ctx, &mock.PublicClient, model.ClientOptionNone)
	require.NoError(t, err)

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
		Name:             &name,
		RedirectURIs:     &redirectUrls,
		Scopes:           &scopes,
		JWKsURI:          &jwksURI,
		LogoURI:          &logoURI,
		AccessTokenLife:  &accessTokenLife,
		RefreshTokenLife: &refreshTokenLife,
	}

	updatedClient, err := db.UpdateClient(ctx, mock.PublicClient.Update(clientUpdate))
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

func TestListClients(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	db, admin, err := InitializeBadgerDB(true)
	defer db.Close()
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

func TestDeleteClient(t *testing.T) {
	ctx := context.Background()
	config.LoadConfig()

	db, _, err := InitializeBadgerDB(true)
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

}
