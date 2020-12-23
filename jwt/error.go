package jwt

import "fmt"

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
