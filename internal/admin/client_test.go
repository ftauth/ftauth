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
	db       *database.BadgerDB
	admin    *model.ClientInfo
	token    *jwt.Token
	tokenJWT string
	r        *mux.Router
}

func (suite *clientTestSuite) SetupSuite() {
	config.LoadConfig()

	db, err := database.InitializeBadgerDB(database.BadgerOptions{InMemory: true, SeedDB: true})
	require.NoError(suite.T(), err)

	admin := db.AdminClient

	suite.db = db
	suite.admin = admin

	suite.r = mux.NewRouter()
	SetupRoutes(suite.r, db)

	token, err := token.IssueAccessToken(admin, &model.User{ID: "test"}, "default admin")
	require.NoError(suite.T(), err)

	suite.token = token

	privateKey := config.Current.DefaultSigningKey()
	require.NoError(suite.T(), err)
	tokenJWT, err := token.Encode(privateKey)
	require.NoError(suite.T(), err)
	suite.tokenJWT = tokenJWT
}

func (suite *clientTestSuite) TearDownTest() {
	suite.db.Reset()
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
				privateKey := config.Current.DefaultSigningKey()
				signed, err := suite.token.Encode(privateKey)
				assert.NoError(t, err)
				header.Add("Authorization", fmt.Sprintf("Bearer %s", signed))
				return header
			},
			statusCode: http.StatusOK,
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
				suite.T().Logf("Got result: %s", resp.Body.Bytes())
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
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", suite.tokenJWT))

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
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", suite.tokenJWT))

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
