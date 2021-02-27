package graphql_test

import (
	"testing"

	"github.com/ftauth/ftauth/pkg/graphql"
	"github.com/ftauth/ftauth/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestBuildGraphQLEnumArray(t *testing.T) {
	tt := []struct {
		name  string
		input interface{}
		want  string
	}{
		{
			name:  "null",
			input: nil,
			want:  "[]",
		},
		{
			name:  "empty string",
			input: "",
			want:  "[]",
		},
		{
			name:  "empty array",
			input: []string{},
			want:  "[]",
		},
		{
			name:  "string",
			input: "hello",
			want:  "[hello]",
		},
		{
			name:  "string array",
			input: []string{"hello", "goodbye"},
			want:  "[hello,goodbye]",
		},
		{
			name: "typed array",
			input: []model.GrantType{
				model.GrantTypeAuthorizationCode,
				model.GrantTypeClientCredentials,
			},
			want: "[authorization_code,client_credentials]",
		},
	}

	for _, test := range tt {
		t.Run(test.name, func(t *testing.T) {
			got := graphql.BuildGraphQLEnumArray(test.input)
			require.Equal(t, test.want, got)
		})
	}
}
