package mock

import (
	"github.com/ftauth/ftauth/pkg/model"
	"github.com/gofrs/uuid"
)

func createUUID() string {
	id, _ := uuid.NewV4()
	return id.String()
}

// DefaultClient represents an auto-generated admin client.
var DefaultClient = model.ClientInfo{
	ID:           createUUID(),
	Name:         "Public Client",
	Type:         model.ClientTypePublic,
	Secret:       "",
	RedirectURIs: []string{"localhost"},
	Scopes: []*model.Scope{
		{
			Name: "default",
		},
	},
	JWKsURI: "http://localhost:8000/jwks.json",
	LogoURI: "",
	GrantTypes: []model.GrantType{
		model.GrantTypeAuthorizationCode,
		model.GrantTypeClientCredentials,
		model.GrantTypeRefreshToken,
	},
	AccessTokenLife:  3600,
	RefreshTokenLife: 86400,
	Providers:        []model.Provider{model.ProviderFTAuth},
}
