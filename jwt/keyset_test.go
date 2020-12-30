package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"reflect"
	"testing"

	"github.com/dnys1/ftoauth/util/base64urluint"
	"github.com/stretchr/testify/require"
)

func TestDecodeKeySet(t *testing.T) {
	tt := []struct {
		jwks  string
		valid bool
		want  func() *KeySet
	}{
		{
			jwks: `{"keys":
			[
			  {"kty":"EC",
			   "crv":"P-256",
			   "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
			   "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
			   "use":"enc",
			   "kid":"1"},
	 
			  {"kty":"RSA",
			   "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
			   "e":"AQAB",
			   "alg":"RS256",
			   "kid":"2011-04-29"}
			]
		  }`,
			valid: true,
			want: func() *KeySet {
				x, err := base64urluint.Decode("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4")
				require.NoError(t, err)

				y, err := base64urluint.Decode("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM")
				require.NoError(t, err)

				key1 := &Key{
					PublicKey: &ecdsa.PublicKey{
						X:     x,
						Y:     y,
						Curve: elliptic.P256(),
					},
					KeyType:      KeyTypeEllipticCurve,
					Curve:        EllipticCurveP256,
					Algorithm:    AlgorithmECDSASHA256,
					X:            (*bigInt)(x),
					Y:            (*bigInt)(y),
					PublicKeyUse: PublicKeyUseEncryption,
					KeyID:        "1",
				}

				n, err := base64urluint.Decode("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")
				require.NoError(t, err)

				e, err := base64urluint.Decode("AQAB")
				require.NoError(t, err)

				key2 := &Key{
					PublicKey: &rsa.PublicKey{
						N: n,
						E: 65537,
					},
					KeyType:   KeyTypeRSA,
					N:         (*bigInt)(n),
					E:         (*bigInt)(e),
					Algorithm: AlgorithmRSASHA256,
					KeyID:     "2011-04-29",
				}

				return &KeySet{
					Keys: []*Key{key1, key2},
				}
			},
		},
	}

	for _, test := range tt {
		keySet, err := DecodeKeySet(test.jwks)
		if test.valid {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
			continue
		}

		require.True(t, reflect.DeepEqual(keySet, test.want()))
	}
}
