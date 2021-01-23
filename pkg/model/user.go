package model

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
