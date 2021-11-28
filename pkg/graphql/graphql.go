package graphql

import (
	"context"

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
