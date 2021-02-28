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
		// {
		// 	jwt:   "eyJ0eXAiOiJhdCtqd3QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiIzY2Y5YTdhYy05MTk4LTQ2OWUtOTJhNy1jYzJmMTVkOGI4N2QiLCJjbGllbnRfaWQiOiIzY2Y5YTdhYy05MTk4LTQ2OWUtOTJhNy1jYzJmMTVkOGI4N2QiLCJleHAiOjE2MTI0Njk5MDcsImlhdCI6MTYxMjQ2NjMwNywiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwianRpIjoiODg4MmNiMGMtNmY1ZS00OGU3LThiZWUtNWFiNDBiNTZmZDMyIiwic2NvcGUiOiJhZG1pbiBkZWZhdWx0Iiwic3ViIjoiQWRtaW4iLCJ1c2VySW5mbyI6eyJpZCI6IkFkbWluIn19.bAVKdzNLEJLK837Rghgusf8Q77hRXiuFguAIfUoZOwQ9ZubZ94rNTTC_j0B_VXTeOSmn3Ma_iJaols2xpN-Z5TMnZzKW5ECk8HsI3LayTE84j-XN32eRZuPkAoqZX4-X0Ri-rlS8w2y59kPYqotWrHcHfczv4eAqaR4GUI-su7I7jlDUkdbdkdwwkenlehsCU9xPRd_Tkqj-qmc0EFsXs1lIhgj2EylAIaib8yiGxuQ-Ebe3pNeBe4HOxLwEEY4EpL_JXxjUtn4PsMH2Gv-dGGk6hZhtd2qJooI-lyh4BG-2OW1l2-XrpzulFHgbKwwbTepFCfu82iJhXzivK-SZOANt-fCmtRrIbVPN50d_otKuc9JYvbRdxttEuMNGHTf_EFPS8DefVsbPCFCLPwkST9ugOPxYV1sB8OFTjx0RHQFu8dJafUUCqb7WIjcvHTDzLbQGY72dBB6YHb5ITJ1H7bOr4HQlkvAjx4-9W9p6AxppKu1AwzO2JVQZFiqQTbBltyCbPNif0yXxrzvSZFzKZHZtaPwjk9DOTnpU40Bu6TGNPOBfQH2xtSVJXIME30JVuq58Mta0VZR7DvEYpEo4u0V7d9KJKdGSjqt1ceYX1NiQoXeV9-TaooULMqy-3l1xh-UdOwzY5cWB803_V_0tjiXaxBRAwh7FE9G6qvLGSgM",
		// 	valid: true,
		// 	want: &Token{
		// 		Header: &Header{
		// 			Type:      TypeAccess,
		// 			Algorithm: AlgorithmRSASHA256,
		// 		},
		// 		Claims: &Claims{
		// 			Audience:       "3cf9a7ac-9198-469e-92a7-cc2f15d8b87d",\
		// 			ExpirationTime: 1612469907,
		// 			IssuedAt:       1612466307,
		// 			Issuer:         "http://localhost:8080",
		// 			JwtID:          "8882cb0c-6f5e-48e7-8bee-5ab40b56fd32",
		// 			Scope:          "admin default",
		// 			Subject:        "Admin",
		// 			CustomClaims: CustomClaims{
		// 				"userInfo": map[string]interface{}{
		// 					"id": "Admin",
		// 				},
		// 			},
		// 		},
		// 	},
		// },
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
