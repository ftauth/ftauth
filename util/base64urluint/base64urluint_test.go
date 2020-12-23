package base64urluint_test

import (
	"math/big"
	"testing"

	"github.com/dnys1/ftoauth/util/base64urluint"
	"github.com/stretchr/testify/require"
)

func Test_Base64UrlUintEncode(t *testing.T) {
	i := int64(65537)
	bi := big.Int{}
	enc := base64urluint.Encode(bi.SetInt64(i))

	require.Equal(t, "AQAB", enc)
}

func Test_Base64UrlUintEncode0(t *testing.T) {
	bi := big.Int{}
	enc := base64urluint.Encode(&bi)

	require.Equal(t, "AA", enc)
}

func Test_Base64UrlUintDecode(t *testing.T) {
	enc := "AQAB"
	bi, err := base64urluint.Decode(enc)
	require.NoError(t, err)
	require.Equal(t, int64(65537), bi.Int64())
	require.Equal(t, []byte{1, 0, 1}, bi.Bytes())
}

func Test_Base64UrlUintDecode0(t *testing.T) {
	enc := "AA"
	bi, err := base64urluint.Decode(enc)
	require.NoError(t, err)
	require.Equal(t, int64(0), bi.Int64())
	require.Equal(t, []byte{}, bi.Bytes())
}
