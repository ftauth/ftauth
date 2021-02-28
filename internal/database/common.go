package database

import (
	"context"

	"github.com/ftauth/ftauth/internal/config"
	"github.com/ftauth/ftauth/pkg/model"
	"github.com/ftauth/ftauth/pkg/util/passwordutil"
	"github.com/gofrs/uuid"
)

func createAdminClient(db Database) (*model.ClientInfo, error) {
	clientID := config.Current.OAuth.Admin.ClientID
	if clientID == "" {
		id, err := uuid.NewV4()
		if err != nil {
			return nil, err
		}
		clientID = id.String()
	}
	adminClient := &model.ClientInfo{
		ID:           clientID,
		Name:         "Admin",
		Type:         model.ClientTypePublic,
		RedirectURIs: []string{"localhost", "myapp://auth"},
		Scopes: []*model.Scope{
			{Name: "default"},
			{Name: "admin"},
		},
		GrantTypes: []model.GrantType{
			model.GrantTypeAuthorizationCode,
			model.GrantTypeRefreshToken,
		},
		AccessTokenLife:  60 * 60,      // 1 hour
		RefreshTokenLife: 60 * 60 * 24, // 1 day
		Providers: []model.Provider{
			model.ProviderFTAuth,
		},
	}
	opt := model.ClientOptionAdmin | model.ClientOption(model.MasterSystemFlag)
	client, err := db.RegisterClient(context.Background(), adminClient, opt)
	if err != nil {
		return nil, err
	}

	userUUID, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	passwordHash, err := passwordutil.GeneratePasswordHash(config.Current.OAuth.Admin.Password)
	if err != nil {
		return nil, err
	}
	user := &model.User{
		ID:           userUUID.String(),
		Username:     config.Current.OAuth.Admin.Username,
		PasswordHash: passwordHash,
	}
	err = db.RegisterUser(context.Background(), user)
	if err != nil {
		return nil, err
	}

	return client, nil
}
