package jwt

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

const key = 0x57B68E846AC65162F1865765B3A1E

func Test_JWKCreation(t *testing.T) {
	key := &Key{
		KeyType:   KeyTypeOctet,
		Algorithm: AlgorithmHMACSHA256,
		K:         "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
	}
	require.NoError(t, key.IsValid())

	_, err := json.Marshal(key)
	require.NoError(t, err)
}

func Test_Decode(t *testing.T) {
	jwk := `
{
	"kty": "oct",
	"k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
}`

	key, err := ParseJWK(jwk)
	require.NoError(t, err)

	// require.True(t, reflect.DeepEqual(*key, Key{
	// 	KeyType:   KeyTypeOctet,
	// 	Algorithm: AlgorithmHMACSHA256,
	// 	K:         "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
	// }))

	t.Logf("Got object: %+v", key)
	t.Logf("Want object: %+v", Key{
		SymmetricKey: []byte{},
		KeyType:      KeyTypeOctet,
		Algorithm:    AlgorithmHMACSHA256,
		K:            "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
	})
}
