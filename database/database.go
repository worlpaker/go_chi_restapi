package database

import "backend/database/pqdb"

// DB represents database interactions.
// All databases can be listed here.
type DB struct {
	Postgres *pqdb.Server
}
