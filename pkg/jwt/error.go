package jwt

import (
	"errors"
	"fmt"
)

func errMissingParameter(name string) error {
	return fmt.Errorf("Missing parameter: %s", name)
}

func errInvalidParameter(name string) error {
	return fmt.Errorf("Invalid parameter: %s", name)
}

func errDuplicateKey(name string) error {
	return fmt.Errorf("Duplicate key: %s", name)
}

func errUnsupportedValue(name, value string) error {
	return fmt.Errorf("Unsupported key-value pair %s: %s", name, value)
}

// Token errors
var (
	ErrMustEncodeFirst     = errors.New("must encode token first")
	ErrMissingPrivateKey   = errors.New("missing private key")
	ErrMissingPublicKey    = errors.New("missing public key")
	ErrMissingSymmetricKey = errors.New("missing symmetric key")
)
