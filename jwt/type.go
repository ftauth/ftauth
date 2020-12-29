package jwt

// Type is the type of JWT, used in the
type Type string

// Valid JWT types
const (
	TypeJWT    Type = "JWT"
	TypeAccess Type = "at+jwt"
	TypeDPoP   Type = "dpop+jwt"
)
