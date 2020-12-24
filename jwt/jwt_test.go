package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Example from Section A.1.1 in RFC 7515
const (
	jwk = `
	{
		"kty": "oct",
		"k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
	}`

	jwt = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

func Test_EncodeJWT(t *testing.T) {
	jwt := &Token{
		Header: &Header{
			Algorithm: AlgorithmHMACSHA256,
			Type:      "JWT",
		},
		Claims: &Claims{
			Issuer:         "dillon",
			Subject:        "test",
			ExpirationTime: time.Now().Add(time.Hour).Unix(),
			IssuedAt:       time.Now().Unix(),
			CustomClaims: map[string]interface{}{
				"key": "value",
			},
		},
	}

	key, err := ParseJWK(jwk)
	require.NoError(t, err)

	enc, err := jwt.Encode(key)
	require.NoError(t, err)

	t.Logf("Got key: %s", enc)
}

func Test_DecodeJWT(t *testing.T) {
	key, err := ParseJWK(jwk)
	require.NoError(t, err)
	require.NotNil(t, key)

	_, err = Decode(jwt)
	require.NoError(t, err)
}
