package jwt

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncode(t *testing.T) {
	tt := []struct {
		jwk   string
		valid bool
		token *Token
		want  string
	}{
		{
			jwk: `{
					"kty": "oct",
					"k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
				}`,
			want:  "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ.LGyv4nF987S4V9z9qm-803XzhHTFe0o82-JsLGEZCjQ",
			valid: true,
			token: &Token{
				Header: &Header{
					Type:      TypeJWT,
					Algorithm: AlgorithmHMACSHA256,
				},
				Claims: &Claims{
					Issuer:         "joe",
					ExpirationTime: 1300819380,
					CustomClaims: map[string]interface{}{
						"http://example.com/is_root": true,
					},
				},
			},
		},
	}

	for _, test := range tt {
		key, err := ParseJWK(test.jwk)
		require.NoError(t, err)

		enc, err := test.token.Encode(key)
		require.NoError(t, err)

		assert.Equal(t, test.want, enc)
	}
}

func TestDecode(t *testing.T) {
	tt := []struct {
		jwt   string
		valid bool
		want  *Token
	}{
		{
			jwt:   "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			valid: true,
			want: &Token{
				Header: &Header{
					Type:      TypeJWT,
					Algorithm: AlgorithmHMACSHA256,
				},
				Claims: &Claims{
					Issuer:         "joe",
					ExpirationTime: 1300819380,
					CustomClaims: CustomClaims{
						"http://example.com/is_root": true,
					},
				},
			},
		},
	}

	for _, test := range tt {
		token, err := Decode(test.jwt)
		require.NoError(t, err)

		t.Logf("Got Header: %+v\n", token.Header)
		t.Logf("Want Header: %+v\n", test.want.Header)
		t.Logf("Got Claims: %+v\n", token.Claims)
		t.Logf("Want Claims: %+v\n", test.want.Claims)

		assert.True(t, reflect.DeepEqual(token.Header, test.want.Header))
		assert.True(t, reflect.DeepEqual(token.Claims, test.want.Claims))
	}
}

func TestIsExpired(t *testing.T) {
	tt := []struct {
		name    string
		token   *Token
		expired bool
	}{
		{
			name: "Empty expiration",
			token: &Token{
				Claims: &Claims{},
			},
			expired: true,
		},
		{
			name: "Expired",
			token: &Token{
				Claims: &Claims{
					ExpirationTime: time.Now().Add(-1 * time.Minute).Unix(),
				},
			},
			expired: true,
		},
		{
			name: "Valid",
			token: &Token{
				Claims: &Claims{
					ExpirationTime: time.Now().Add(1 * time.Minute).Unix(),
				},
			},
			expired: false,
		},
		{
			name: "Within Buffer",
			token: &Token{
				Claims: &Claims{
					ExpirationTime: time.Now().Add(-1 * time.Second).Unix(),
				},
			},
			expired: false,
		},
	}

	for _, test := range tt {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expired, test.token.IsExpired())
		})
	}
}
