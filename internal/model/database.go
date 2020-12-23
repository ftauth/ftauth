package model

// DatabaseType represents the backend for the database.
type DatabaseType string

// The different supported database backends.
const (
	DatabaseTypePostgres DatabaseType = "postgres"
	DatabaseTypeOracle   DatabaseType = "oracle"
)
