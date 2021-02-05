package model

import "errors"

// User is a user/resource owner.
type User struct {
	ID           string `db:"id" json:"id,omitempty"` // uuid
	Username     string `db:"username" json:"username,omitempty"`
	PasswordHash string `db:"password_hash" json:"password_hash,omitempty"`
	FirstName    string `db:"first_name" json:"first_name,omitempty"`
	LastName     string `db:"last_name" json:"last_name,omitempty"`
	Email        string `db:"email" json:"email,omitempty"`
	PhoneNumber  string `db:"phone_number" json:"phone_number,omitempty"`
	Provider     string `db:"provider" json:"provider,omitempty"`
}

func (u *User) Valid() error {
	if u.ID == "" {
		return errors.New("missing ID")
	}
	return nil
}

// ToUserData converts a user object to a user data object for sharing.
func (u *User) ToUserData() *UserData {
	return &UserData{
		ID:          u.ID,
		Username:    u.Username,
		FirstName:   u.FirstName,
		LastName:    u.LastName,
		Email:       u.Email,
		PhoneNumber: u.PhoneNumber,
		Provider:    u.Provider,
	}
}

// UserData holds the key user data for sharing externally.
type UserData struct {
	ID          string `db:"id" json:"id,omitempty"` // uuid
	Username    string `db:"username" json:"username,omitempty"`
	FirstName   string `db:"first_name" json:"first_name,omitempty"`
	LastName    string `db:"last_name" json:"last_name,omitempty"`
	Email       string `db:"email" json:"email,omitempty"`
	PhoneNumber string `db:"phone_number" json:"phone_number,omitempty"`
	Provider    string `db:"provider" json:"provider,omitempty"`
}
