package graphql

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ftauth/ftauth/pkg/jwt"
	"github.com/ftauth/ftauth/pkg/util"
)

// Client holds connection-related info for a Dgraph database.
type Client struct {
	URL        string
	privateKey *jwt.Key
}

// Request holds the parameters for a GraphQL query. Query must be included.
type Request struct {
	Query         string                 `json:"query"`
	OperationName string                 `json:"operationName,omitempty"`
	Variables     map[string]interface{} `json:"variables,omitempty"`

	// Response should be a pointer to a struct to deserialize
	// the JSON response into.
	Response interface{} `json:"-"`
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

// NewClient creates a GraphQL client from an FTAuth client ID, DB connection URL, and RSA private key.
// The private key must match the public key registered in the database for any requests to be validated.
func NewClient(url string, privateKey *jwt.Key) (*Client, error) {
	if err := privateKey.IsValid(); err != nil {
		return nil, err
	}
	client := &Client{
		URL:        url,
		privateKey: privateKey,
	}
	return client, nil
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

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.URL, &b)
	if err != nil {
		return nil, err
	}

	jwt, err := client.createJWTWithClaims(map[string]interface{}{
		"ROLE": "ADMIN",
	})
	if err != nil {
		return nil, err
	}

	fmt.Println("Sending with JWT: ", jwt)

	request.Header.Set("Cache-Control", "no-cache")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Auth-Token", jwt)

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

func (client *Client) createJWTWithClaims(claims map[string]interface{}) (string, error) {
	token := &jwt.Token{
		Header: &jwt.Header{
			Type:      jwt.TypeJWT,
			Algorithm: jwt.AlgorithmRSASHA256,
			KeyID:     client.privateKey.KeyID,
		},
		Claims: &jwt.Claims{
			Audience:       "ftauth",
			NotBefore:      time.Now().Unix(),
			ExpirationTime: time.Now().Add(time.Minute).Unix(),
			CustomClaims: jwt.CustomClaims{
				"https://dgraph.io/jwt/claims": claims,
			},
		},
	}

	jwt, err := token.Encode(client.privateKey)
	if err != nil {
		return "", err
	}

	return jwt, nil
}
