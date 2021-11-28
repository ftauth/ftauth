package dgraph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ftauth/ftauth/pkg/graphql"
	"github.com/ftauth/ftauth/pkg/jwt"
)

// GraphQLClient holds connection-related info for a Dgraph database.
type GraphQLClient struct {
	url        *url.URL
	jwtToken   *jwt.Token
	privateKey *jwt.Key
	apiKey     string
	claims     map[string]interface{}
}

// NewClient creates a GraphQL client from a RSA private key. The private key must match the public key
// registered in the database for any requests to be validated.
//
// Alternatively, clients should obtain a JWT token from FTAuth and use it with NewClientFromJWT.
func NewClient(_url string, privateKey *jwt.Key, adminApiKey string, claims map[string]interface{}) (*GraphQLClient, error) {
	if err := privateKey.IsValid(); err != nil {
		return nil, err
	}

	endpoint, err := url.Parse(_url)
	if err != nil {
		return nil, err
	}
	endpoint.Path = "/graphql"

	client := &GraphQLClient{
		url:        endpoint,
		privateKey: privateKey,
		apiKey:     adminApiKey,
		claims:     claims,
	}
	return client, nil
}

// NewClientFromJWT creates a GraphQL client using a pre-signed FTAuth JWT token. It must
// include a valid clientID ("client_id" or "aud" field for FTAuth tokens) in order to be
// validated by the database.
func NewClientFromJWT(_url string, token *jwt.Token) (*GraphQLClient, error) {
	if err := token.Valid(); err != nil {
		return nil, err
	}

	ftauthClaims := token.Claims.CustomClaims["https://ftauth.io"]
	if ftauthClaims == nil {
		return nil, errors.New("invalid FTAuth token")
	}
	ftauthMap, ok := ftauthClaims.(map[string]interface{})
	if !ok {
		return nil, errors.New("invalid FTAuth token")
	}

	endpoint, err := url.Parse(_url)
	if err != nil {
		return nil, err
	}
	client := &GraphQLClient{
		url:      endpoint,
		jwtToken: token,
		claims:   ftauthMap,
	}
	return client, nil
}

func (client *GraphQLClient) withAuthToken(request *http.Request) error {
	var token string
	var err error
	if client.jwtToken == nil {
		token, err = client.createJWTWithClaims()
	} else {
		token, err = client.jwtToken.Raw()
	}
	if err != nil {
		return err
	}
	_ = token
	// request.Header.Set("Authorization", "Bearer "+token)

	if client.apiKey != "" {
		request.Header.Set("X-Auth-Token", client.apiKey)
	}

	return nil
}

// Ping checks the health of the database.
func (client *GraphQLClient) Ping(ctx context.Context) error {
	probeURL := client.url.ResolveReference(&url.URL{Path: "/probe/graphql"})

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL.String(), nil)
	if err != nil {
		return err
	}

	err = client.withAuthToken(request)
	if err != nil {
		return err
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	// Healthy cluster indicated by 200 status
	if response.StatusCode == http.StatusOK {
		return nil
	}

	b, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	return fmt.Errorf("%d %s", response.StatusCode, b)
}

// UpdateSchema updates the schema returning the schema that was updated, the generated schema
// for that schema, and any error that occurred during the process.
func (client *GraphQLClient) UpdateSchema(ctx context.Context, schema string) error {
	adminURL := client.url.ResolveReference(&url.URL{Path: "/admin/schema"})

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, adminURL.String(), strings.NewReader(schema))
	if err != nil {
		return err
	}

	err = client.withAuthToken(request)
	if err != nil {
		return err
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	// Successful validate indicated by 200 status
	if response.StatusCode == http.StatusOK {
		return nil
	}

	b, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	return fmt.Errorf("%d %s", response.StatusCode, b)
}

// Do sends a GraphQL request to the server and decodes the response into the given value.
func (client *GraphQLClient) Do(ctx context.Context, req *graphql.Request) (*graphql.Response, error) {
	if err := req.Valid(); err != nil {
		return nil, err
	}

	var b bytes.Buffer
	err := json.NewEncoder(&b).Encode(req)
	if err != nil {
		return nil, err
	}

	var url string
	if req.URL == "" {
		url = client.URL()
	} else {
		url = req.URL
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &b)
	if err != nil {
		return nil, err
	}

	err = client.withAuthToken(request)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Cache-Control", "no-cache")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	resp := graphql.Response{
		Data: req.Response,
	}
	if err := json.NewDecoder(response.Body).Decode(&resp); err != nil {
		return nil, err
	}

	if len(resp.Errors) > 0 {
		return &resp, fmt.Errorf(resp.Errors[0].Message)
	}

	return &resp, nil
}

func (client *GraphQLClient) createJWTWithClaims() (string, error) {
	token := &jwt.Token{
		Header: &jwt.Header{
			Type:      jwt.TypeJWT,
			Algorithm: jwt.AlgorithmRSASHA256,
			KeyID:     client.privateKey.KeyID,
		},
		Claims: &jwt.Claims{
			NotBefore:      time.Now().Unix(),
			ExpirationTime: time.Now().Add(time.Minute).Unix(),
			CustomClaims: jwt.CustomClaims{
				"https://ftauth.io": client.claims,
			},
		},
	}

	jwt, err := token.Encode(client.privateKey)
	if err != nil {
		return "", err
	}

	return jwt, nil
}

func (client *GraphQLClient) URL() string {
	return client.url.String()
}

var _ graphql.Client = (*GraphQLClient)(nil)
