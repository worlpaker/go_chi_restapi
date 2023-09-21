package pqdb

import (
	"backend/config"
	Log "backend/internal/log"
	"database/sql"
	"log"

	_ "github.com/lib/pq"
)

type Server struct {
	Client *sql.DB
}

// ConnectDB to PosgtreSQL
func ConnectDB() *sql.DB {
	db, err := sql.Open("postgres", config.DbSource)
	if Log.Err(err) {
		panic(err.Error())
	}
	if err = db.Ping(); Log.Err(err) {
		panic(err)
	}
	log.Println("connected database:", config.DbSource)
	return db
}
