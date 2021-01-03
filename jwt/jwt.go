package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/dnys1/ftoauth/util/base64url"
	"github.com/mitchellh/mapstructure"
)

// Token is a JSON Web Token (JWT)
type Token struct {
	raw       string  // cached raw string
	Header    *Header // The header values
	Claims    *Claims // The claims (registered and custom)
	Signature []byte  // The signature of the token
}

// Common JWT processing errors
var (
	ErrUnsignedToken        = errors.New("unsigned tokens not allowed")
	ErrInvalidJWTFormat     = errors.New("invalid JWT format")
	ErrInvalidHeaderFormat  = errors.New("invalid header format")
	ErrInvalidPayloadFormat = errors.New("invalid payload format")
	ErrMismatchedAlgorithms = errors.New("algorithms do not match between key and token")
	ErrInvalidSignature     = errors.New("invalid signature")
)

// Header holds metadata about a JWT, including JWS or JWE-specific algorithm
// and certificate information.
type Header struct {
	Type        Type   `json:"typ,omitempty"` // JWT or dpop+jwt
	ContentType string `json:"cty,omitempty"`

	// JWS Headers (will be different for JWE)
	Algorithm                      Algorithm `json:"alg,omitempty"` // Required
	JWKSetURL                      string    `json:"jwu,omitempty"`
	JWK                            *Key      `json:"jwk,omitempty"` // Required for DPoP tokens
	KeyID                          string    `json:"kid,omitempty"`
	X509URL                        string    `json:"x5u,omitempty"`
	X509CertificateChain           []string  `json:"x5c,omitempty"`
	X509CertificateSHA1Thumbprint  string    `json:"x5t,omitempty"`
	X509CertificateSHA256Thumprint string    `json:"x5t#S256,omitempty"`
}

// IsValid checks whether the header contains all required fields
// and is properly formatted. Returns an error if not.
func (h *Header) IsValid() error {
	if h.Type == "" {
		return errMissingParameter("typ")
	}
	if h.Algorithm == "" {
		return errMissingParameter("alg")
	}
	switch h.Type {
	case TypeDPoP:
		if h.JWK == nil {
			return errMissingParameter("jwk")
		}
	}
	return nil
}

// CustomClaims holds custom claims information outside the
// registered claims fields.
type CustomClaims map[string]interface{}

var registeredClaims = []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti"}

func isRegisteredClaim(claim string) bool {
	for _, c := range registeredClaims {
		if c == claim {
			return true
		}
	}
	return false
}

// Claims holds all the claims this token provides.
type Claims struct {
	Issuer         string             `mapstructure:"iss,omitempty" json:"iss,omitempty"` // Required
	Subject        string             `mapstructure:"sub,omitempty" json:"sub,omitempty"` // Required
	Audience       string             `mapstructure:"aud,omitempty" json:"aud,omitempty"` // Required
	ExpirationTime int64              `mapstructure:"exp,omitempty" json:"exp,omitempty"` // Required for non-DPoP tokens
	NotBefore      int64              `mapstructure:"nbf,omitempty" json:"nbf,omitempty"`
	IssuedAt       int64              `mapstructure:"iat,omitempty" json:"iat,omitempty"` // Required
	JwtID          string             `mapstructure:"jti,omitempty" json:"jti,omitempty"` // Required for DPoP tokens
	Nonce          string             `mapstructure:"nonce,omitempty" json:"nonce,omitempty"`
	Confirmation   *ConfirmationClaim `mapstructure:"cnf,omitempty" json:"cnf,omitempty"`
	ClientID       string             `mapstructure:"client_id,omitempty" json:"client_id,omitempty"` // Required for non-DPoP tokens
	Scope          string             `mapstructure:"scope,omitempty" json:"scope,omitempty"`         // Required for non-DPoP tokens

	// DPoP claims
	HTTPMethod string `mapstructure:"htm,omitempty" json:"htm,omitempty"` // The HTTP method for the request to which the JWT is attached
	HTTPURI    string `mapstructure:"htu,omitempty" json:"htu,omitempty"` // The HTTP URI used for the request, without query and fragment parts

	CustomClaims CustomClaims `mapstructure:",remain" json:"-"`
}

// ConfirmationClaim holds public key information for cryptographically verifying
// a sender holds the corresponding private key.
type ConfirmationClaim struct {
	JWK              *Key   `mapstructure:"jwk,omitempty" json:"jwk,omitempty"`
	SHA256Thumbprint string `mapstructure:"jkt,omitempty" json:"jkt,omitempty"`
}

// IsValid checks whether the payload contains all required fields
// and is properly formatted. Returns an error if not.
func (c *Claims) IsValid(typ Type) error {
	if typ == TypeAccess || typ == TypeDPoP {
		if c.Issuer == "" {
			return errMissingParameter("iss")
		}
		if c.Subject == "" {
			return errMissingParameter("sub")
		}
		if c.Audience == "" {
			return errMissingParameter("aud")
		}
		if c.IssuedAt == 0 {
			return errMissingParameter("iat")
		}
		switch typ {
		case TypeAccess:
			if c.ExpirationTime == 0 {
				return errMissingParameter("exp")
			}
			if c.ClientID == "" {
				return errMissingParameter("client_id")
			}
			if c.Scope == "" {
				return errMissingParameter("scope")
			}
		case TypeDPoP:
			if c.JwtID == "" {
				return errMissingParameter("jti")
			}
			if c.HTTPMethod == "" {
				return errMissingParameter("htm")
			}
			if c.HTTPURI == "" {
				return errMissingParameter("htu")
			}
		}
	}
	return nil
}

func (t *Token) encodeUnsigned() (string, error) {
	header, err := json.Marshal(t.Header)
	if err != nil {
		return "", err
	}

	payload, err := json.Marshal(t.Claims)
	if err != nil {
		return "", err
	}
	if t.Claims.CustomClaims != nil {
		var payloadMap map[string]interface{}
		if err := json.Unmarshal(payload, &payloadMap); err != nil {
			return "", err
		}
		for key, value := range t.Claims.CustomClaims {
			if !isRegisteredClaim(key) {
				payloadMap[key] = value
			}
		}
		payload, err = json.Marshal(payloadMap)
		if err != nil {
			return "", err
		}
	}

	encHeader := base64url.Encode(header)
	encPayload := base64url.Encode(payload)

	return fmt.Sprintf("%s.%s", encHeader, encPayload), nil
}

// Raw returns the raw token string. Must run Encode first on generated tokens.
func (t *Token) Raw() (string, error) {
	if t.raw != "" {
		return t.raw, nil
	}

	return "", ErrMustEncodeFirst
}

// Encode signs and encodes the token in base64 for transfer on the wire.
func (t *Token) Encode(key *Key) (string, error) {
	unsigned, err := t.encodeUnsigned()
	if err != nil {
		return "", err
	}

	signer := key.Signer()
	signed, err := signer([]byte(unsigned))
	if err != nil {
		return "", err
	}

	signature := base64url.Encode(signed)
	t.raw = fmt.Sprintf("%s.%s", unsigned, signature)
	return t.raw, nil
}

// Decode parses and verifies a token's signature.
func Decode(token string) (*Token, error) {
	fields := strings.Split(token, ".")
	if len(fields) == 2 {
		return nil, ErrUnsignedToken
	}
	if len(fields) != 3 {
		return nil, ErrInvalidJWTFormat
	}

	headerJSON, err := base64url.Decode(fields[0])
	if err != nil {
		return nil, ErrInvalidHeaderFormat
	}
	var header Header
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, ErrInvalidHeaderFormat
	}

	// Generate keys if JWK is included
	if header.JWK != nil {
		err = header.JWK.generateKey()
		if err != nil {
			return nil, err
		}
	}
	if err := header.IsValid(); err != nil {
		return nil, err
	}

	payloadJSON, err := base64url.Decode(fields[1])
	if err != nil {
		return nil, ErrInvalidPayloadFormat
	}
	var payloadMap map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &payloadMap); err != nil {
		return nil, ErrInvalidPayloadFormat
	}
	var payload Claims
	if err := mapstructure.Decode(payloadMap, &payload); err != nil {
		return nil, ErrInvalidPayloadFormat
	}
	if err := payload.IsValid(header.Type); err != nil {
		return nil, err
	}

	signature, err := base64url.Decode(fields[2])
	if err != nil {
		return nil, ErrInvalidSignature
	}

	return &Token{
		raw:       token,
		Header:    &header,
		Claims:    &payload,
		Signature: signature,
	}, nil
}

// Verify compares the JWT signature with the expected one based
// off the provided key.
func (t *Token) Verify(key *Key) error {
	// Verify the algorithm of the key matches that of the token
	if t.Header.Algorithm != key.Algorithm {
		return ErrMismatchedAlgorithms
	}

	// Compare signature with expected based off client Key
	headerJSON, err := json.Marshal(t.Header)
	if err != nil {
		return ErrInvalidHeaderFormat
	}
	header := base64url.Encode(headerJSON)
	payloadJSON, err := json.Marshal(t.Claims)
	if err != nil {
		return ErrInvalidPayloadFormat
	}
	payload := base64url.Encode(payloadJSON)

	body := fmt.Sprintf("%s.%s", header, payload)
	verifier := key.Verifier()
	err = verifier([]byte(body), t.Signature)
	if err != nil {
		return ErrInvalidSignature
	}

	return nil
}
