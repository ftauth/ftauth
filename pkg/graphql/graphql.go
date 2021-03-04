package graphql

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

	"github.com/ftauth/ftauth/pkg/jwt"
	"github.com/ftauth/ftauth/pkg/util"
)

// Client holds connection-related info for a Dgraph database.
type Client struct {
	URL        string
	jwtToken   *jwt.Token
	privateKey *jwt.Key
	claims     map[string]interface{}
}

// Request holds the parameters for a GraphQL query. Query must be included.
type Request struct {
	Query         string                 `json:"query"`
	OperationName string                 `json:"operationName,omitempty"`
	Variables     map[string]interface{} `json:"variables,omitempty"`

	// Response should be a pointer to a struct to deserialize
	// the JSON response into.
	Response interface{} `json:"-"`

	// URL, if different than client URL (e.g. /graphql)
	URL string `json:"-"`
}

// Valid checks whether the request has required parameters.
func (req *Request) Valid() error {
	if req.Query == "" {
		return util.ErrMissingParameter("Query")
	}
	return nil
}

// Error is an error returned from the database for a GraphQL query.
type Error struct {
	Message   string `json:"message"`
	Locations []struct {
		Line   int `json:"line"`
		Column int `json:"column"`
	} `json:"locations"`
}

// Response is the response returned from the database for a GraphQL query.
type Response struct {
	Data   interface{} `json:"data"`
	Errors []Error     `json:"errors"`
}

// NewClient creates a GraphQL client from a RSA private key. The private key must match the public key
// registered in the database for any requests to be validated.
//
// Alternatively, clients should obtain a JWT token from FTAuth and use it with NewClientFromJWT.
func NewClient(url string, privateKey *jwt.Key, claims map[string]interface{}) (*Client, error) {
	if err := privateKey.IsValid(); err != nil {
		return nil, err
	}
	client := &Client{
		URL:        url,
		privateKey: privateKey,
		claims:     claims,
	}
	return client, nil
}

// NewClientFromJWT creates a GraphQL client using a pre-signed FTAuth JWT token. It must
// include a valid clientID ("client_id" or "aud" field for FTAuth tokens) in order to be
// validated by the database.
func NewClientFromJWT(url string, token *jwt.Token) (*Client, error) {
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

	client := &Client{
		URL:      url,
		jwtToken: token,
		claims:   ftauthMap,
	}
	return client, nil
}

func (client *Client) withAuthToken(request *http.Request) error {
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
	request.Header.Set("X-Auth-Token", token)

	return nil
}

// Ping checks the health of the database.
func (client *Client) Ping(ctx context.Context) error {
	probeURL, err := url.Parse(client.URL)
	if err != nil {
		return err
	}
	probeURL.Path = "/probe/graphql"

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

// ValidateSchema checks whether the given schema can be applied to the database.
func (client *Client) ValidateSchema(ctx context.Context, schema string) error {
	validateURL, err := url.Parse(client.URL)
	if err != nil {
		return err
	}
	validateURL.Path = "/admin/schema/validate"

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, validateURL.String(), strings.NewReader(schema))
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

	b, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	// Successful validate indicated by 200 status
	if response.StatusCode == http.StatusOK {
		return nil
	}

	return fmt.Errorf("%d %s", response.StatusCode, b)
}

// UpdateSchema updates the schema returning the schema that was updated, the generated schema
// for that schema, and any error that occurred during the process.
func (client *Client) UpdateSchema(ctx context.Context, schema string) error {
	adminURL, err := url.Parse(client.URL)
	if err != nil {
		return err
	}
	adminURL.Path = "/admin/schema"

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
func (client *Client) Do(ctx context.Context, req *Request) (*Response, error) {
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
		url = client.URL
	} else {
		url = req.URL
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &b)
	if err != nil {
		return nil, err
	}

	err = client.withAuthToken(request)

	request.Header.Set("Cache-Control", "no-cache")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	resp := Response{
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

func (client *Client) createJWTWithClaims() (string, error) {
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
