package config

import (
	"fmt"
	"os"
)

var (
	ServerPort = ":8000"
	// Ex. local:
	// DbSource = "postgres://postgres:postgrespw@localhost:5432/postgres?sslmode=disable"
	pg_user     = os.Getenv("POSTGRES_USER")
	pg_pw       = os.Getenv("POSTGRES_PASSWORD")
	pg_db       = os.Getenv("POSTGRES_DB")
	// Docker:
	DbSource    = fmt.Sprintf("postgres://%s:%s@postgres:5432/%s?sslmode=disable", pg_user, pg_pw, pg_db)
	TokenSecret = os.Getenv("tokensecret")
)
