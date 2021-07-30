package jwt

import (
	"errors"
	"fmt"
)

func errMissingParameter(name string) error {
	return fmt.Errorf("missing parameter: %s", name)
}

func errInvalidParameter(name string) error {
	return fmt.Errorf("invalid parameter: %s", name)
}

func errDuplicateKey(name string) error {
	return fmt.Errorf("duplicate key: %s", name)
}

func errUnsupportedValue(name, value string) error {
	return fmt.Errorf("unsupported key-value pair %s: %s", name, value)
}

// Token errors
var (
	ErrMustEncodeFirst     = errors.New("must encode token first")
	ErrMissingPrivateKey   = errors.New("missing private key")
	ErrMissingPublicKey    = errors.New("missing public key")
	ErrMissingSymmetricKey = errors.New("missing symmetric key")
)
