package model

// CodeChallengeMethod is the type of code challenge used for PKCE
type CodeChallengeMethod string

const (
	// CodeChallengeMethodSHA256 uses the SHA256 hash of the code challenge.
	CodeChallengeMethodSHA256 CodeChallengeMethod = "S256"

	// CodeChallengeMethodPlain uses the plaintext of the code challenge.
	// Only S256 is supported in FTOAuth, although the PKCE RFC supports
	// this method as well.
	CodeChallengeMethodPlain CodeChallengeMethod = "plain"
)

// IsValid returns whether or not this method is supported.
func (method CodeChallengeMethod) IsValid() bool {
	switch method {
	case CodeChallengeMethodSHA256:
		return true
	}

	return false
}
