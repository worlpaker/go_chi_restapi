package handlers

import (
	"backend/database/pqdb"
)

type Server struct {
	DB *pqdb.Server
}
