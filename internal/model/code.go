package model

import (
	"bytes"
	"crypto/rand"
	"io"

	"github.com/dnys1/ftoauth/util/base64url"
)

// GenerateAuthorizationCode generates a unique, random authorization code.
func GenerateAuthorizationCode() string {
	rng := rand.Reader
	var bf bytes.Buffer
	io.CopyN(&bf, rng, 16)
	return base64url.Encode(bf.Bytes())
}
