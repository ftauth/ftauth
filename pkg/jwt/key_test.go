package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"reflect"
	"testing"

	"github.com/ftauth/ftauth/pkg/util/base64url"
	"github.com/ftauth/ftauth/pkg/util/base64urluint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarshal(t *testing.T) {
	key := &Key{
		KeyType:   KeyTypeOctet,
		Algorithm: AlgorithmHMACSHA256,
		K:         "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
	}
	require.NoError(t, key.IsValid())

	_, err := json.Marshal(key)
	assert.NoError(t, err)
}

func TestParseJWK(t *testing.T) {
	tt := []struct {
		jwk   string
		valid bool
		want  func() *Key
	}{
		{
			jwk: `{
					"kty": "oct",
					"k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
				}`,
			valid: true,
			want: func() *Key {
				b, err := base64url.Decode("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")
				require.NoError(t, err)

				return &Key{
					SymmetricKey: b,
					KeyType:      KeyTypeOctet,
					Algorithm:    AlgorithmHMACSHA256,
					K:            "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
				}
			},
		},
		{
			jwk: `{
				"kty":"EC",
				"crv":"P-256",
				"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
				"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
				"use":"enc",
				"kid":"1"
			}`,
			valid: true,
			want: func() *Key {
				x, err := base64urluint.Decode("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4")
				require.NoError(t, err)

				y, err := base64urluint.Decode("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM")
				require.NoError(t, err)

				return &Key{
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
			},
		},
		{
			jwk: `{
				"kty":"RSA",
				"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				"e":"AQAB",
				"alg":"RS256",
				"kid":"2011-04-29"
				}`,
			valid: true,
			want: func() *Key {
				n, err := base64urluint.Decode("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")
				require.NoError(t, err)

				e, err := base64urluint.Decode("AQAB")
				require.NoError(t, err)

				return &Key{
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
			},
		},
		{
			jwk: `{
				"kty":"EC",
				"crv":"P-256",
				"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
				"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
				"d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
				"use":"enc",
				"kid":"1"
				}`,
			valid: true,
			want: func() *Key {
				x, err := base64urluint.Decode("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4")
				require.NoError(t, err)

				y, err := base64urluint.Decode("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM")
				require.NoError(t, err)

				d, err := base64urluint.Decode("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE")
				require.NoError(t, err)

				pub := ecdsa.PublicKey{
					Curve: elliptic.P256(),
					X:     x,
					Y:     y,
				}
				return &Key{
					PublicKey: &pub,
					PrivateKey: &ecdsa.PrivateKey{
						PublicKey: pub,
						D:         d,
					},
					KeyType:      KeyTypeEllipticCurve,
					Curve:        EllipticCurveP256,
					Algorithm:    AlgorithmECDSASHA256,
					X:            (*bigInt)(x),
					Y:            (*bigInt)(y),
					D:            (*bigInt)(d),
					PublicKeyUse: PublicKeyUseEncryption,
					KeyID:        "1",
				}
			},
		},
		{
			jwk: `{
				"kty":"RSA",
				"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				"e":"AQAB",
				"d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
				"p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
				"q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
				"dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
				"dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
				"qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
				"alg":"RS256",
				"kid":"2011-04-29"
				}`,
			valid: true,
			want: func() *Key {
				n, err := base64urluint.Decode("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")
				require.NoError(t, err)

				e, err := base64urluint.Decode("AQAB")
				require.NoError(t, err)

				d, err := base64urluint.Decode("X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q")
				require.NoError(t, err)

				p, err := base64urluint.Decode("83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs")
				require.NoError(t, err)

				q, err := base64urluint.Decode("3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk")
				require.NoError(t, err)

				dp, err := base64urluint.Decode("G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0")
				require.NoError(t, err)

				dq, err := base64urluint.Decode("s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk")
				require.NoError(t, err)

				qi, err := base64urluint.Decode("GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU")
				require.NoError(t, err)

				pub := rsa.PublicKey{
					N: n,
					E: 65537,
				}
				return &Key{
					PublicKey: &pub,
					PrivateKey: &rsa.PrivateKey{
						PublicKey: pub,
						D:         d,
						Primes:    []*big.Int{p, q},
						Precomputed: rsa.PrecomputedValues{
							Dp:   dp,
							Dq:   dq,
							Qinv: qi,
						},
					},
					KeyType:   KeyTypeRSA,
					Algorithm: AlgorithmRSASHA256,
					N:         (*bigInt)(n),
					E:         (*bigInt)(e),
					D:         (*bigInt)(d),
					P:         (*bigInt)(p),
					Q:         (*bigInt)(q),
					DP:        (*bigInt)(dp),
					DQ:        (*bigInt)(dq),
					QI:        (*bigInt)(qi),
					KeyID:     "2011-04-29",
				}
			},
		},
	}

	for _, test := range tt {
		key, err := ParseJWK(test.jwk)
		if test.valid {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
			continue
		}

		t.Logf("Got: %+v\n", key)
		t.Logf("Want: %+v\n", test.want())

		assert.True(t, reflect.DeepEqual(key, test.want()))
	}
}

func TestSigner(t *testing.T) {
	tt := []struct {
		jwk     string
		payload string
	}{
		{
			jwk: `{
				"kty":"oct",
				"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
			}`,
			payload: "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
		},
		{
			jwk: `{
				"kty":"RSA",
				"alg":"RS256",
				"n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
				"e":"AQAB",
				"d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
				"p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
				"q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
				"dp":"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
				"dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
				"qi":"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
			}`,
			payload: "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
		},
		{
			jwk: `{
				"kty":"EC",
				"crv":"P-256",
				"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
				"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
				"d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
		   	}`,
			payload: "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
		},
		{
			jwk: `{
				"kty":"EC",
				"crv":"P-521",
				"x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",
				"y":"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2",
				"d":"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C"
			   }`,
			payload: "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA",
		},
		{
			jwk: `{
				"kty":"RSA",
				"alg":"RS256",
				"n":"3Ax2o3178fqgLNjYaLg-qbySGSr06-U3W4yvh7hPdxDLZKhP6t0QKnquzhFlJaNgnO1UrWpYRhSBKhgrxq0tqANia8fuAMQRfAVmSLKSsljaMnvEty879z2c692dIv0pFWycW8GyeGepVGnL6Ir1zi8Y9QBQqv1qTl608-e7xmFr9aksPXwpiJNsk2jIXdVSKA0ekwady5ed6sl4UOPd8kzNlRisGspjIa_AFevqLRIYG1RINt6MKiiIn64_Ld3FKXxsGsWslPfUKw3J1QKWzM2h1R90njXaiB0ljKL-6yG7FCbRXbXCS392zxdzhpYJ_PqaotD_1G4RZGQsy2ZZwQ",
				"e":"AQAB",
				"d":"ae0l_zWcwLNg_7WzF1X59ENuIOdo11WT_GIQ7UhwGGThRCcxsWGRMqG0HEaLZj7rdx9YL9KNg87DDrxr9kvPOp3GdxPbIktAD2-Z-UzdCTV0c_DYlUYLm8zxCSm5RuqPKF0MN69adlOQU65KFjsucH6DiQ0JyAYNcoRsnyziW3ANkHXUos_a9VtoC5m37YxmFPWpJISFxXyrwCbkWnjcLNgOVmxhXoBJws8puKEK7l3dvT66iflNjM3pWnMnPKYuL-TE4vrWLeHV_g-WyrFHgOBwDNFoKf6hzvxu_9aTzoFtEO-UtAyy4jy7bHw3790c4WPohhhLSTIIBqOq8qeK8Q",
				"p":"91dvYONbsSlPJG0W8DELirOLbwLI4VVgcpE_NW_D9i-Te5wS1kB3mFHogRxbKkfakF7ahG076mfSrBYlDfHpspXXNO5Uk57VrNcYVxaGFul7Jsdec7zE079Nc91PQ0R1RY6Ab9KBsrj1A_D1ji_E0mvezUjLLzpkMiuZ1e_bfi8",
				"q":"48BxIIzjTdd5Rm_8czPciwnyjy9GMHO6lWrZ-aRaPoIhMagMnvExdItZLMzAE97InmZDG0HtfCe1JF1rtNKMmrkktMHqUgzSXyhKD4AA0KCOOq2qPfjrM6lO8pmAj6DrI84PPbZtOpaqiWJOZJuvhOUjH0sFL9rx4A9w1qC1Gw8",
				"dp":"bHeHfHG4ECURc-PzHzoi2ZyLFQ-fkFGkjhlsIr70rM2IW7jB-fsjd0TUNWp-ADiqfI1cPp64m78UACtl7Iud9JcJXUj3BhWtlrJtFiPmgb26J_NeVFr_5ewKxzjSPamT1AD-CgvCnOHHcQcGaGhCZBSyDExT7k4pCmdcexlIpDk",
				"dq":"hkUVLLiC5YhsAh_ReGWR1xK1Qr7_JV-FF8PX4DqJzaJQSYMmdaoCmw_wMd5AOzazldb6Jx62EOUkAN1mu0MKC8mtHzfXmine-KS7DOpNELInR-bMoB6ZI2rklVf0GDkph4FbMOnU-Z6LydUAHIZAcxvXmgJTe4Qb5xmTT6WNP_c",
				"qi":"MsV7NmbXeKeCS0TXMhv_EhGV0kCO-OCO_l55_eLGzvq1-OGqHG3JVuWLIF5m1EMsG2Z8gFhEQENtZ0AOFQx2O9XiNg2dT5I-_itnX_9TWFpbI06mCqrQx21VkovMpFwxY_wsbDDtoSBzLIXZQ21q2sL7ObjFc_DKcj2WrBx10Ps"
				}`,
			payload: "eyJ0eXAiOiJhdCtqd3QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJlZTFkZTVhZC1jNGE4LTQxNWMtOGZmNi03NjljYTBmZDNiZjEiLCJjbGllbnRfaWQiOiJlZTFkZTVhZC1jNGE4LTQxNWMtOGZmNi03NjljYTBmZDNiZjEiLCJleHAiOjE2MTA4NDc1NzAsImlhdCI6MTYxMDg0Mzk3MCwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwianRpIjoiMTllMmFmN2ItMzY2NS00MmVjLWFkZGEtMDg3ZDY4MDJlNzJlIiwic2NvcGUiOiJkZWZhdWx0Iiwic3ViIjoiZGlsbG9ubnlzIiwidXNlckluZm8iOnsiaWQiOiJkaWxsb25ueXMifX0",
		},
	}

	for _, test := range tt {
		key, err := ParseJWK(test.jwk)
		require.NoError(t, err)

		signer := key.Signer()
		signature, err := signer([]byte(test.payload))
		assert.NoError(t, err)

		verifier := key.Verifier()
		err = verifier([]byte(test.payload), signature)
		assert.NoError(t, err)
	}
}

func TestSomeTest(t *testing.T) {
	const payload = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"

	const privatePem = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA3Ax2o3178fqgLNjYaLg+qbySGSr06+U3W4yvh7hPdxDLZKhP
6t0QKnquzhFlJaNgnO1UrWpYRhSBKhgrxq0tqANia8fuAMQRfAVmSLKSsljaMnvE
ty879z2c692dIv0pFWycW8GyeGepVGnL6Ir1zi8Y9QBQqv1qTl608+e7xmFr9aks
PXwpiJNsk2jIXdVSKA0ekwady5ed6sl4UOPd8kzNlRisGspjIa/AFevqLRIYG1RI
Nt6MKiiIn64/Ld3FKXxsGsWslPfUKw3J1QKWzM2h1R90njXaiB0ljKL+6yG7FCbR
XbXCS392zxdzhpYJ/PqaotD/1G4RZGQsy2ZZwQIDAQABAoIBAGntJf81nMCzYP+1
sxdV+fRDbiDnaNdVk/xiEO1IcBhk4UQnMbFhkTKhtBxGi2Y+63cfWC/SjYPOww68
a/ZLzzqdxncT2yJLQA9vmflM3Qk1dHPw2JVGC5vM8QkpuUbqjyhdDDevWnZTkFOu
ShY7LnB+g4kNCcgGDXKEbJ8s4ltwDZB11KLP2vVbaAuZt+2MZhT1qSSEhcV8q8Am
5Fp43CzYDlZsYV6AScLPKbihCu5d3b0+uon5TYzN6VpzJzymLi/kxOL61i3h1f4P
lsqxR4DgcAzRaCn+oc78bv/Wk86BbRDvlLQMsuI8u2x8N+/dHOFj6IYYS0kyCAaj
qvKnivECgYEA91dvYONbsSlPJG0W8DELirOLbwLI4VVgcpE/NW/D9i+Te5wS1kB3
mFHogRxbKkfakF7ahG076mfSrBYlDfHpspXXNO5Uk57VrNcYVxaGFul7Jsdec7zE
079Nc91PQ0R1RY6Ab9KBsrj1A/D1ji/E0mvezUjLLzpkMiuZ1e/bfi8CgYEA48Bx
IIzjTdd5Rm/8czPciwnyjy9GMHO6lWrZ+aRaPoIhMagMnvExdItZLMzAE97InmZD
G0HtfCe1JF1rtNKMmrkktMHqUgzSXyhKD4AA0KCOOq2qPfjrM6lO8pmAj6DrI84P
PbZtOpaqiWJOZJuvhOUjH0sFL9rx4A9w1qC1Gw8CgYBsd4d8cbgQJRFz4/MfOiLZ
nIsVD5+QUaSOGWwivvSszYhbuMH5+yN3RNQ1an4AOKp8jVw+nribvxQAK2Xsi530
lwldSPcGFa2Wsm0WI+aBvbon815UWv/l7ArHONI9qZPUAP4KC8Kc4cdxBwZoaEJk
FLIMTFPuTikKZ1x7GUikOQKBgQCGRRUsuILliGwCH9F4ZZHXErVCvv8lX4UXw9fg
OonNolBJgyZ1qgKbD/Ax3kA7NrOV1vonHrYQ5SQA3Wa7QwoLya0fN9eaKd74pLsM
6k0QsidH5sygHpkjauSVV/QYOSmHgVsw6dT5novJ1QAchkBzG9eaAlN7hBvnGZNP
pY0/9wKBgDLFezZm13ingktE1zIb/xIRldJAjvjgjv5eef3ixs76tfjhqhxtyVbl
iyBeZtRDLBtmfIBYREBDbWdADhUMdjvV4jYNnU+SPv4rZ1//U1haWyNOpgqq0Mdt
VZKLzKRcMWP8LGww7aEgcyyF2UNtatrC+zm4xXPwynI9lqwcddD7
-----END RSA PRIVATE KEY-----
	`

	p, _ := pem.Decode([]byte(privatePem))

	rsaKey, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	require.NoError(t, err)

	privKey, err := NewJWKFromRSAPrivateKey(rsaKey)
	require.NoError(t, err)

	pubKey, err := NewJWKFromRSAPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)

	signer := privKey.Signer()
	sig, err := signer([]byte(payload))
	assert.NoError(t, err)

	verifier := pubKey.Verifier()
	err = verifier([]byte(payload), sig)
	assert.NoError(t, err)
}

func TestVerifier(t *testing.T) {
	tt := []struct {
		jwk       string
		payload   string
		signature string
	}{
		{
			jwk: `{
				"kty":"oct",
				"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
			}`,
			payload:   "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
			signature: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		},
		{
			jwk: `{
				"kty":"RSA",
				"alg":"RS256",
				"n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
				"e":"AQAB",
				"d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
				"p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
				"q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
				"dp":"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
				"dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
				"qi":"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
			}`,
			payload:   "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
			signature: "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw",
		},
		{
			jwk: `{
				"kty":"EC",
				"crv":"P-256",
				"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
				"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
				"d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
		   	}`,
			payload:   "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
			signature: "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q",
		},
		{
			jwk: `{
				"kty":"EC",
				"crv":"P-521",
				"x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",
				"y":"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2",
				"d":"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C"
			   }`,
			payload:   "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA",
			signature: "AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn",
		},
		{
			jwk: `{
				"kty":"RSA",
				"alg":"RS256",
				"n":"3Ax2o3178fqgLNjYaLg-qbySGSr06-U3W4yvh7hPdxDLZKhP6t0QKnquzhFlJaNgnO1UrWpYRhSBKhgrxq0tqANia8fuAMQRfAVmSLKSsljaMnvEty879z2c692dIv0pFWycW8GyeGepVGnL6Ir1zi8Y9QBQqv1qTl608-e7xmFr9aksPXwpiJNsk2jIXdVSKA0ekwady5ed6sl4UOPd8kzNlRisGspjIa_AFevqLRIYG1RINt6MKiiIn64_Ld3FKXxsGsWslPfUKw3J1QKWzM2h1R90njXaiB0ljKL-6yG7FCbRXbXCS392zxdzhpYJ_PqaotD_1G4RZGQsy2ZZwQ",
				"e":"AQAB",
				"d":"ae0l_zWcwLNg_7WzF1X59ENuIOdo11WT_GIQ7UhwGGThRCcxsWGRMqG0HEaLZj7rdx9YL9KNg87DDrxr9kvPOp3GdxPbIktAD2-Z-UzdCTV0c_DYlUYLm8zxCSm5RuqPKF0MN69adlOQU65KFjsucH6DiQ0JyAYNcoRsnyziW3ANkHXUos_a9VtoC5m37YxmFPWpJISFxXyrwCbkWnjcLNgOVmxhXoBJws8puKEK7l3dvT66iflNjM3pWnMnPKYuL-TE4vrWLeHV_g-WyrFHgOBwDNFoKf6hzvxu_9aTzoFtEO-UtAyy4jy7bHw3790c4WPohhhLSTIIBqOq8qeK8Q",
				"p":"91dvYONbsSlPJG0W8DELirOLbwLI4VVgcpE_NW_D9i-Te5wS1kB3mFHogRxbKkfakF7ahG076mfSrBYlDfHpspXXNO5Uk57VrNcYVxaGFul7Jsdec7zE079Nc91PQ0R1RY6Ab9KBsrj1A_D1ji_E0mvezUjLLzpkMiuZ1e_bfi8",
				"q":"48BxIIzjTdd5Rm_8czPciwnyjy9GMHO6lWrZ-aRaPoIhMagMnvExdItZLMzAE97InmZDG0HtfCe1JF1rtNKMmrkktMHqUgzSXyhKD4AA0KCOOq2qPfjrM6lO8pmAj6DrI84PPbZtOpaqiWJOZJuvhOUjH0sFL9rx4A9w1qC1Gw8",
				"dp":"bHeHfHG4ECURc-PzHzoi2ZyLFQ-fkFGkjhlsIr70rM2IW7jB-fsjd0TUNWp-ADiqfI1cPp64m78UACtl7Iud9JcJXUj3BhWtlrJtFiPmgb26J_NeVFr_5ewKxzjSPamT1AD-CgvCnOHHcQcGaGhCZBSyDExT7k4pCmdcexlIpDk",
				"dq":"hkUVLLiC5YhsAh_ReGWR1xK1Qr7_JV-FF8PX4DqJzaJQSYMmdaoCmw_wMd5AOzazldb6Jx62EOUkAN1mu0MKC8mtHzfXmine-KS7DOpNELInR-bMoB6ZI2rklVf0GDkph4FbMOnU-Z6LydUAHIZAcxvXmgJTe4Qb5xmTT6WNP_c",
				"qi":"MsV7NmbXeKeCS0TXMhv_EhGV0kCO-OCO_l55_eLGzvq1-OGqHG3JVuWLIF5m1EMsG2Z8gFhEQENtZ0AOFQx2O9XiNg2dT5I-_itnX_9TWFpbI06mCqrQx21VkovMpFwxY_wsbDDtoSBzLIXZQ21q2sL7ObjFc_DKcj2WrBx10Ps"
				}`,
			payload:   "eyJ0eXAiOiJhdCtqd3QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJlZTFkZTVhZC1jNGE4LTQxNWMtOGZmNi03NjljYTBmZDNiZjEiLCJjbGllbnRfaWQiOiJlZTFkZTVhZC1jNGE4LTQxNWMtOGZmNi03NjljYTBmZDNiZjEiLCJleHAiOjE2MTA4NDc1NzAsImlhdCI6MTYxMDg0Mzk3MCwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwianRpIjoiMTllMmFmN2ItMzY2NS00MmVjLWFkZGEtMDg3ZDY4MDJlNzJlIiwic2NvcGUiOiJkZWZhdWx0Iiwic3ViIjoiZGlsbG9ubnlzIiwidXNlckluZm8iOnsiaWQiOiJkaWxsb25ueXMifX0",
			signature: "xKCZr8gVwrrh24UmtQKJkx_qul8JLg6eInZH9NBYgn4K1NlaS9IEs0LU3EWdvDTW6S-93RADzF68G7BSG5gkb3_OMchTE19anhC-IR6pXMuwkC9PnDo_UaKxsGsK9KjRj8jGhIh8NZESx_qU9ACOZ2VKfJLIP9oYaAUQXFHsnEMUcDyG1YUvA7re97PigsWCpVuKGRW1TSzzYxqQfKjf7Ur5C49umaZoQkpnpMUUl89SoNCmeDFfYoifh0L7QghNKeyNs0B236iASr7XI0cPPPGAloR0nw-FsaG3hswQAi33LpTz4m2QIS_xYW3vKAoPMRZYVs28_cU5tlqAy8QRrw",
		},
	}

	for _, test := range tt {
		key, err := ParseJWK(test.jwk)
		require.NoError(t, err)

		sig, err := base64url.Decode(test.signature)
		require.NoError(t, err)

		verifier := key.Verifier()
		err = verifier([]byte(test.payload), sig)
		assert.NoError(t, err)
	}
}

func TestThumbprint(t *testing.T) {
	tt := []struct {
		jwk  string
		want string
	}{
		{
			jwk: `{
				"kty": "RSA",
				"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				"e": "AQAB",
				"alg": "RS256",
				"kid": "2011-04-29"
			   }`,
			want: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
		},
	}

	for _, test := range tt {
		key, err := ParseJWK(test.jwk)
		require.NoError(t, err)

		got, err := key.Thumbprint()
		assert.NoError(t, err)
		assert.Equal(t, test.want, got)
	}
}
