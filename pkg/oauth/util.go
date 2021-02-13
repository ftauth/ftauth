package oauth

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"io"
	"math/rand"
	"strings"

	"github.com/ftauth/ftauth/pkg/util/base64url"
)

const characterSet = `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~`

// GenerateCodeChallenge produces a new code challenge.
func GenerateCodeChallenge() (string, string) {
	const N = 128
	numChars := len(characterSet)
	sb := new(strings.Builder)
	for i := 0; i < N; i++ {
		rIdx := rand.Intn(numChars)
		sb.WriteByte(characterSet[rIdx])
	}
	s := sb.String()
	hash := sha256.Sum256([]byte(s))
	return s, base64url.Encode(hash[:])
}

// GenerateState produces a new random state.
func GenerateState() (string, error) {
	r := crand.Reader
	var b bytes.Buffer
	_, err := io.CopyN(&b, r, 16)
	if err != nil {
		return "", err
	}
	return base64url.Encode(b.Bytes()), nil
}
