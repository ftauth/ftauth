package graphql

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/ftauth/ftauth/pkg/util"
)

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

// Client is a GraphQL endpoint client.
type Client interface {
	URL() string
	Do(ctx context.Context, req *Request) (*Response, error)
}

func NewClient(_url string, headers map[string]string) (*DefaultClient, error) {
	endpoint, err := url.Parse(_url)
	if err != nil {
		return nil, err
	}
	endpoint.Path = "/graphql"

	return &DefaultClient{
		url:     endpoint.String(),
		headers: headers,
	}, nil
}

type DefaultClient struct {
	url     string
	headers map[string]string
}

func (client *DefaultClient) URL() string {
	return client.url
}

func (client *DefaultClient) Do(ctx context.Context, req *Request) (*Response, error) {
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

	request.Header.Set("Cache-Control", "no-cache")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	for key, value := range client.headers {
		request.Header.Set(key, value)
	}

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
