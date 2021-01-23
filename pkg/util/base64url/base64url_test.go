package base64url

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	plaintext = "abcdefghijjklmnopqrstuvwxyz0123456789`~-_=+[]\\{}|;':\",./<>?"
	base64enc = "YWJjZGVmZ2hpamprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OWB-LV89K1tdXHt9fDsnOiIsLi88Pj8"
)

func Test_Base64UrlEncode(t *testing.T) {
	enc := Encode([]byte(plaintext))
	assert.Equal(t, base64enc, enc)
}

func Test_Base64UrlDecode(t *testing.T) {
	dec, err := Decode(base64enc)
	assert.NoError(t, err)
	assert.Equal(t, []byte(plaintext), dec)
}
