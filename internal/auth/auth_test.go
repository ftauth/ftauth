package auth

import "testing"

func Test_AuthorizationHeader(t *testing.T) {
	tt := []struct {
		header string
		valid  bool
	}{
		{
			"Bearer A",
			true,
		},
		{
			"Bearer 12345===",
			true,
		},
		{
			"Bearer",
			false,
		},
		{
			"Bearer ",
			false,
		},
		{
			"Bearer        1456===",
			true,
		},
		{
			"Bearer 😂😂",
			false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.header, func(t *testing.T) {
			_, err := ParseBearerAuthorizationHeader(tc.header)
			valid := err == nil
			if valid != tc.valid {
				t.Error("Mismatched test: ", err)
			}
		})
	}
}
