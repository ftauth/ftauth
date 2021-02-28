package model

// Provider represents the authentication provider, i.e. Google or Microsoft.
type Provider string

// Supported authentication providers
const (
	ProviderFTAuth    Provider = "ftauth"
	ProviderApple     Provider = "apple"
	ProviderGoogle    Provider = "google"
	ProviderMicrosoft Provider = "microsoft"
)

// GQL returns the GraphQL representation.
func (provider Provider) GQL() string {
	return string(provider)
}

// ProviderData holds provider-specific information
type ProviderData struct {
	Provider Provider
	Username string
	Email    string
}
