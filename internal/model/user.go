package model

// User is a user/resource owner.
type User struct {
	ID           string `db:"id" json:"id"` // uuid
	Username     string `db:"username" json:"username"`
	PasswordHash string `db:"password_hash" json:"-"`
	FirstName    string `db:"first_name" json:"first_name"`
	LastName     string `db:"last_name" json:"last_name"`
	Email        string `db:"email" json:"email"`
	PhoneNumber  string `db:"phone_number" json:"phone_number"`
	Provider     string `db:"provider" json:"provider"`
}
