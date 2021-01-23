package base64url

import "encoding/base64"

// Encode encodes the given bytes using strict base64url encoding.
func Encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// Decode decodes the given string using strict base64url encoding.
func Decode(str string) ([]byte, error) {
	return base64.RawURLEncoding.Strict().DecodeString(str)
}
