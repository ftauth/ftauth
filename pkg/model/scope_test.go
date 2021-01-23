package model_test

import (
	"testing"

	"github.com/ftauth/ftauth/pkg/model"
	"github.com/stretchr/testify/assert"
)

func TestParseScope(t *testing.T) {
	tt := []struct {
		scopes string
		want   []string
		valid  bool
	}{
		{
			scopes: "default admin",
			want:   []string{"default", "admin"},
			valid:  true,
		},
		{
			scopes: "invalidchars😂",
			valid:  false,
		},
	}

	for _, test := range tt {
		scopes, err := model.ParseScope(test.scopes)
		if test.valid {
			assert.Equalf(t, test.want, scopes, "Got: %v, Want: %v", scopes, test.want)
		} else {
			assert.Errorf(t, err, "Want error, got tokens: %v", scopes)
		}
	}
}
