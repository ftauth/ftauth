package base64urluint_test

import (
	"math/big"
	"reflect"
	"testing"

	"github.com/dnys1/ftoauth/util/base64urluint"
	"github.com/stretchr/testify/require"
)

func TestEncode(t *testing.T) {
	tt := []struct {
		input func() *big.Int
		want  string
	}{
		{
			input: func() *big.Int {
				bi := big.Int{}
				return bi.SetInt64(65537)
			},
			want: "AQAB",
		},
		{
			input: func() *big.Int {
				return &big.Int{}
			},
			want: "AA",
		},
	}

	for _, test := range tt {
		got := base64urluint.Encode(test.input())

		require.Equal(t, test.want, got)
	}
}

func Test_Base64UrlUintDecode(t *testing.T) {
	tt := []struct {
		input string
		valid bool
		want  func() *big.Int
	}{
		{
			input: "AQAB",
			valid: true,
			want: func() *big.Int {
				bi := &big.Int{}
				return bi.SetBytes([]byte{1, 0, 1})
			},
		},
		{
			input: "AA",
			valid: true,
			want: func() *big.Int {
				bi := &big.Int{}
				return bi.SetBytes([]byte{0})
			},
		},
		{
			input: "",
			valid: true,
			want: func() *big.Int {
				return nil
			},
		},
		{
			input: "Invalid Base 64 URL ===",
			valid: false,
		},
	}

	for _, test := range tt {
		got, err := base64urluint.Decode(test.input)
		if test.valid {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
			continue
		}

		require.Truef(t, reflect.DeepEqual(got, test.want()), "Input: %s, Got: %+v, Want: %+v", test.input, got, test.want())
	}
}
