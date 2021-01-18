package model

const (
	// LocalhostRedirectURI is a special redirect URI value for local development. Exact matching
	// is not performed. Instead, any URI with host equal to 'localhost' is accepted. This is to ease
	// development efforts by not worrying about registering ports.
	LocalhostRedirectURI string = "localhost"
)
