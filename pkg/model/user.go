package model

import (
	_ "embed" // GraphQL embeds
	"fmt"

	"github.com/ftauth/ftauth/pkg/graphql"
	"github.com/ftauth/ftauth/pkg/util"
)

// GraphQL embeds
var (
	//go:embed gql/fragments/AllUserInfo.graphql
	AllUserInfo string
)

// User is a user/resource owner.
type User struct {
	ID           string         `json:"id"` // uuid
	Subject      string         `json:"sub,omitempty"`
	ClientID     string         `json:"client_id"`
	Username     string         `json:"username,omitempty"`
	PasswordHash string         `json:"password_hash,omitempty"`
	FirstName    string         `json:"first_name,omitempty"`
	LastName     string         `json:"last_name,omitempty"`
	Email        string         `json:"email,omitempty"`
	PhoneNumber  string         `json:"phone_number,omitempty"`
	Scopes       []*Scope       `json:"scopes,omitempty"`
	ProviderData []ProviderData `json:"-"`
}

// Valid checks whether the User has the required information.
func (u *User) Valid() error {
	if u.ID == "" {
		return util.ErrMissingParameter("ID")
	}
	if u.ClientID == "" {
		return util.ErrMissingParameter("ClientID")
	}
	return nil
}

// GQL returns the GraphQL representation.
func (u *User) GQL() string {
	gql := `
	{
		id: "%s"
		client_id: "%s"
		username: "%s"
		password_hash: "%s"
		first_name: "%s"
		last_name: "%s"
		email: "%s"
		phone_number: "%s"
		scopes: %s
	}
	`

	return fmt.Sprintf(
		gql,
		u.ID,
		u.ClientID,
		u.Username,
		u.PasswordHash,
		u.FirstName,
		u.LastName,
		u.Email,
		u.PhoneNumber,
		graphql.MarshalGQL(u.Scopes),
	)
}

// ToUserData converts a user object to a user data object for sharing.
func (u *User) ToUserData() *UserData {
	return &UserData{
		ID:           u.ID,
		ClientID:     u.ClientID,
		Username:     u.Username,
		FirstName:    u.FirstName,
		LastName:     u.LastName,
		Email:        u.Email,
		PhoneNumber:  u.PhoneNumber,
		Scopes:       u.Scopes,
		ProviderData: u.ProviderData,
	}
}

// UserData holds the key user data for sharing externally.
type UserData struct {
	ID           string         `json:"id"` // uuid
	ClientID     string         `json:"client_id"`
	Username     string         `json:"username,omitempty"`
	FirstName    string         `json:"first_name,omitempty"`
	LastName     string         `json:"last_name,omitempty"`
	Email        string         `json:"email,omitempty"`
	PhoneNumber  string         `json:"phone_number,omitempty"`
	Scopes       []*Scope       `json:"scopes,omitempty"`
	ProviderData []ProviderData `json:"provider_data,omitempty"`
}
