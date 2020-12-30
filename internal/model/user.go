package model

// User is a user/resource owner.
type User struct {
	ID           string `db:"id"` // uuid
	Username     string `db:"username"`
	PasswordHash string `db:"password_hash"`
}
