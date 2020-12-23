package base64urluint

import (
	"math/big"

	"github.com/dnys1/ftoauth/util/base64url"
)

// Encode returns the base64-url encoded representation
// of the big-endian octet sequence as defined in
// [RFC 7518 2](https://www.rfc-editor.org/rfc/rfc7518.html#section-2)
func Encode(i *big.Int) string {
	// Get the big-endian bytes
	bytes := i.Bytes()

	// The octet sequence MUST utilize the minimum number of octets
	// needed to represent the value.
	for i, val := range bytes {
		if val > 0 {
			return base64url.Encode(bytes[i:])
		}
	}

	return base64url.Encode([]byte{})
}

// Decode returns the BigInt represented by the base64url-encoded string.
func Decode(str string) (*big.Int, error) {
	b, err := base64url.Decode(str)
	if err != nil {
		return nil, err
	}
	bint := big.Int{}
	return bint.SetBytes(b), nil
}
