package auth

import (
	"fmt"
	"testing"

	"github.com/ftauth/ftauth/pkg/oauth"
	"github.com/ftauth/ftauth/pkg/util/base64url"
	"github.com/stretchr/testify/require"
)

func TestParseBearerAuthorizationHeader(t *testing.T) {
	tt := []struct {
		header string
		valid  bool
	}{
		{
			"Bearer A",
			true,
		},
		{
			"Bearer 12345===",
			true,
		},
		{
			"Bearer",
			false,
		},
		{
			"Bearer ",
			false,
		},
		{
			"Bearer        1456===",
			true,
		},
		{
			"Bearer 😂😂",
			false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.header, func(t *testing.T) {
			_, err := ParseBearerAuthorizationHeader(tc.header)
			valid := err == nil
			if valid != tc.valid {
				t.Error("Mismatched test: ", err)
			}
		})
	}
}

func TestParseBasicAuthorizationHeader(t *testing.T) {
	clientID := "clientID12"
	clientSecret := "clientSecret12"

	tt := []struct {
		name   string
		header func() string
		valid  bool
	}{
		{
			name: "Empty header",
			header: func() string {
				return ""
			},
			valid: false,
		},
		{
			name: "Empty header value",
			header: func() string {
				return "Basic "
			},
			valid: false,
		},
		{
			name: "Non-base64 encoded",
			header: func() string {
				return "Basic id:password"
			},
			valid: false,
		},
		{
			name: "Base64 URL encoded",
			header: func() string {
				return "Basic " + base64url.Encode([]byte(fmt.Sprintf("%s:%s", clientID, clientSecret)))
			},
			valid: false,
		},
		{
			name: "Valid format",
			header: func() string {
				return oauth.CreateBasicAuthorization(clientID, clientSecret)
			},
			valid: true,
		},
	}

	for _, test := range tt {
		t.Run(test.name, func(t *testing.T) {
			pClientID, pClientSecret, err := ParseBasicAuthorizationHeader(test.header())
			if test.valid {
				require.NoError(t, err)
				require.Equal(t, pClientID, clientID)
				require.Equal(t, pClientSecret, clientSecret)
			} else {
				require.Error(t, err)
			}
		})
	}
}
