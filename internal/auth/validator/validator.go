package validator

// Validator handles validation of parameters and requests.
type Validator interface {
	Validate() error
}
