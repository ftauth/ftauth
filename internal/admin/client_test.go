package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/ftauth/ftauth/internal/config"
	"github.com/ftauth/ftauth/internal/database"
	"github.com/ftauth/ftauth/internal/mock"
	"github.com/ftauth/ftauth/internal/token"
	"github.com/ftauth/ftauth/pkg/jwt"
	"github.com/ftauth/ftauth/pkg/model"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type clientTestSuite struct {
	suite.Suite
	db            *database.BadgerDB
	admin         *model.ClientInfo
	adminToken    *jwt.Token
	adminTokenJWT string
	demoTokenJWT  string
	r             *mux.Router
}

func (suite *clientTestSuite) SetupSuite() {
	ctx := context.Background()
	config.LoadConfig()

	db, err := database.NewBadgerDB(true, nil)
	require.NoError(suite.T(), err)

	admin := db.AdminClient

	suite.db = db
	suite.admin = admin

	// Setup demo client
	demoClient, err := db.RegisterClient(ctx, &mock.DefaultClient, model.ClientOptionNone)
	require.NoError(suite.T(), err)

	suite.r = mux.NewRouter()
	SetupRoutes(suite.r, admin.ID, db, nil)

	scopes := []*model.Scope{
		{Name: config.Current.OAuth.Scopes.Default},
	}
	adminScopes := append([]*model.Scope{}, scopes...)
	adminScopes = append(adminScopes, &model.Scope{Name: "admin"})

	adminUser, err := model.NewUser("test", "password", admin.ID, adminScopes)
	require.NoError(suite.T(), err)

	adminToken, err := token.IssueAccessToken(admin, adminUser, "default admin")
	require.NoError(suite.T(), err)

	suite.adminToken = adminToken

	// Create demo token
	demoUser, err := model.NewUser("test", "password", demoClient.ID, scopes)
	require.NoError(suite.T(), err)

	demoToken, err := token.IssueAccessToken(demoClient, demoUser, "default")
	require.NoError(suite.T(), err)

	privateKey := config.Current.DefaultSigningKey()
	require.NoError(suite.T(), err)
	tokenJWT, err := adminToken.Encode(privateKey)
	require.NoError(suite.T(), err)
	suite.adminTokenJWT = tokenJWT

	demoTokenJWT, err := demoToken.Encode(privateKey)
	require.NoError(suite.T(), err)
	suite.demoTokenJWT = demoTokenJWT
}

func (suite *clientTestSuite) SetupTest() {
	admin, err := database.CreateAdminClient(context.Background(), suite.db)
	require.NoError(suite.T(), err)
	suite.admin = admin
}

func (suite *clientTestSuite) TearDownTest() {
	suite.db.DropAll(context.Background())
}

func (suite *clientTestSuite) TearDownSuite() {
	suite.db.Close()
}

func TestClientTestSuite(t *testing.T) {
	suite.Run(t, new(clientTestSuite))
}

func (suite *clientTestSuite) TestListClients() {
	t := suite.T()

	tt := []struct {
		name       string
		headers    func() http.Header
		statusCode int
	}{
		{
			name: "Empty Header",
			headers: func() http.Header {
				return http.Header{}
			},
			statusCode: http.StatusUnauthorized,
		},
		{
			name: "Valid Auth",
			headers: func() http.Header {
				header := http.Header{}
				header.Add("Authorization", fmt.Sprintf("Bearer %s", suite.adminTokenJWT))
				return header
			},
			statusCode: http.StatusOK,
		},
		{
			name: "Invalid Client",
			headers: func() http.Header {
				header := http.Header{}
				header.Add("Authorization", fmt.Sprintf("Bearer %s", suite.demoTokenJWT))
				return header
			},
			statusCode: http.StatusUnauthorized,
		},
	}

	for _, test := range tt {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/admin/clients", nil)
			req.Header = test.headers()

			resp := httptest.NewRecorder()

			suite.r.ServeHTTP(resp, req)
			require.Equal(t, resp.Result().StatusCode, test.statusCode)

			if test.statusCode == http.StatusOK {
				var clients []*model.ClientInfo
				err := json.NewDecoder(resp.Body).Decode(&clients)
				assert.NoError(t, err)

				require.Len(t, clients, 1)
				assert.True(t, reflect.DeepEqual(suite.admin, clients[0]))
			}
		})
	}
}

func (suite *clientTestSuite) TestAddClient() {
	t := suite.T()

	tt := []struct {
		name       string
		req        *model.ClientInfo
		reqJSON    string
		statusCode int
	}{
		{
			name:       "Bad JSON",
			reqJSON:    "This is bad JSON",
			statusCode: http.StatusInternalServerError,
		},
		{
			name:       "Bad Client JSON",
			reqJSON:    "{}",
			statusCode: http.StatusBadRequest,
		},
		{
			name:       "Good Client",
			req:        &mock.PublicClient,
			statusCode: http.StatusOK,
		},
	}

	for _, test := range tt {
		t.Run(test.name, func(t *testing.T) {
			var b []byte
			if test.reqJSON != "" {
				b = []byte(test.reqJSON)
			} else {
				var err error
				b, err = json.Marshal(test.req)
				require.NoError(t, err)
			}

			bb := bytes.NewBuffer(b)
			req := httptest.NewRequest(http.MethodPost, "/api/admin/clients", bb)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", suite.adminTokenJWT))

			resp := httptest.NewRecorder()

			suite.r.ServeHTTP(resp, req)

			assert.Equal(t, test.statusCode, resp.Result().StatusCode)
			if test.statusCode == http.StatusOK {
				var response model.ClientInfo
				err := json.NewDecoder(resp.Body).Decode(&response)
				require.NoError(t, err)
				assert.True(t, reflect.DeepEqual(&response, test.req), "Got: %#v\nExpect: %#v", response, test.req)
			}
		})
	}
}

func (suite *clientTestSuite) TestUpdateClient() {
	t := suite.T()

	tt := []struct {
		name       string
		req        func() (client *model.ClientInfoUpdate, json string)
		original   model.ClientInfo
		statusCode int
	}{
		{
			name:     "Bad JSON",
			original: mock.PublicClient,
			req: func() (*model.ClientInfoUpdate, string) {
				return nil, "This is bad JSON"
			},
			statusCode: http.StatusInternalServerError,
		},
		{
			name:     "Empty Update",
			original: mock.PublicClient,
			req: func() (*model.ClientInfoUpdate, string) {
				return &model.ClientInfoUpdate{}, "{}"
			},
			statusCode: http.StatusOK,
		},
		{
			name:     "Good Client",
			original: mock.PublicClient,
			req: func() (*model.ClientInfoUpdate, string) {
				updatedName := "Updated Client Name"
				update := &model.ClientInfoUpdate{
					Name: &updatedName,
				}
				b, err := json.Marshal(update)
				require.NoError(t, err)

				return update, string(b)
			},
			statusCode: http.StatusOK,
		},
	}

	for _, test := range tt {
		t.Run(test.name, func(t *testing.T) {
			original := test.original
			_, err := suite.db.RegisterClient(context.Background(), &original, model.ClientOptionNone)
			require.NoError(t, err)

			update, reqJSON := test.req()

			bb := bytes.NewBuffer([]byte(reqJSON))
			req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/admin/clients/%s", original.ID), bb)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", suite.adminTokenJWT))

			resp := httptest.NewRecorder()

			suite.r.ServeHTTP(resp, req)

			assert.Equal(t, test.statusCode, resp.Result().StatusCode)
			if test.statusCode == http.StatusOK {
				var response model.ClientInfo
				err := json.NewDecoder(resp.Body).Decode(&response)
				require.NoError(t, err)

				expected := original.Update(*update)
				assert.Truef(t, reflect.DeepEqual(expected, &response), "Got: %#v\nExpected: %#v", response, expected)
			}
		})
	}
}
