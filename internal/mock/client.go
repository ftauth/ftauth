package mock

import (
	"github.com/ftauth/ftauth/pkg/model"
	"github.com/gofrs/uuid"
)

func uuidMust() string {
	id, err := uuid.NewV4()
	if err != nil {
		panic(err)
	}
	return id.String()
}

// Mock clients
var (
	PublicClient = model.ClientInfo{
		ID:           uuidMust(),
		Name:         "Test Public Client",
		Type:         model.ClientTypePublic,
		RedirectURIs: []string{"localhost"},
		Scopes: []*model.Scope{
			{Name: "default"},
		},
		GrantTypes: []model.GrantType{
			model.GrantTypeAuthorizationCode,
			model.GrantTypeRefreshToken,
		},
		AccessTokenLife:  60 * 60,
		RefreshTokenLife: 60 * 60 * 24,
	}

	AdminClient = model.ClientInfo{
		ID:           uuidMust(),
		Name:         "Test Admin Client",
		Type:         model.ClientTypePublic,
		RedirectURIs: []string{"localhost"},
		Scopes: []*model.Scope{
			{Name: "default"},
			{Name: "admin"},
		},
		GrantTypes: []model.GrantType{
			model.GrantTypeAuthorizationCode,
			model.GrantTypeRefreshToken,
		},
		AccessTokenLife:  60 * 60,
		RefreshTokenLife: 60 * 60 * 24,
	}

	ConfidentialClient = model.ClientInfo{
		ID:           uuidMust(),
		Name:         "Test Confidential Client",
		Type:         model.ClientTypeConfidential,
		Secret:       "secret",
		RedirectURIs: []string{"localhost"},
		Scopes: []*model.Scope{
			{Name: "default"},
		},
		GrantTypes: []model.GrantType{
			model.GrantTypeClientCredentials,
		},
		AccessTokenLife:  60 * 60,
		RefreshTokenLife: 60 * 60 * 24,
	}
)
