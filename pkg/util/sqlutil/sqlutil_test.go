package sqlutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseArray(t *testing.T) {
	tt := []struct {
		input string
		want  []string
	}{
		{
			input: "{}",
			want:  []string(nil),
		},
		{
			input: "{'default'}",
			want:  []string{"default"},
		},
		{
			input: "{'admin','default'}",
			want:  []string{"admin", "default"},
		},
	}

	for _, test := range tt {
		got := ParseArray(test.input)
		assert.Equal(t, test.want, got)
	}
}

func TestGenerateArrayString(t *testing.T) {
	tt := []struct {
		input []string
		want  string
	}{
		{
			input: []string{},
			want:  "{}",
		},
		{
			input: []string(nil),
			want:  "{}",
		},
		{
			input: []string{"default"},
			want:  "{'default'}",
		},
		{
			input: []string{"admin", "default"},
			want:  "{'admin','default'}",
		},
	}

	for _, test := range tt {
		got := GenerateArrayString(test.input)
		assert.Equal(t, test.want, got)
	}
}
