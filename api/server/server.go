package server

import (
	"backend/api/handlers"
	"backend/api/routers"
	"backend/database/pqdb"
	"database/sql"
	"log"
	"net/http"

	"github.com/go-chi/chi"
)

// NewAuth for server
func NewAuth() (*chi.Mux, *sql.DB) {
	r := chi.NewRouter()
	d := pqdb.ConnectDB()
	return r, d
}

// NewServer creates new connection to server
func NewServer(r *chi.Mux, db *sql.DB) *routers.Server {
	s := &routers.Server{
		Router: r,
		Handlers: &handlers.Server{
			DB: &pqdb.Server{
				Client: db,
			},
		},
	}
	return s
}

// Start to server
func Start(port string) error {
	r, d := NewAuth()
	s := NewServer(r, d)
	s.SetupRouters()
	log.Println("API Listen ON", port)
	return http.ListenAndServe(port, s.Router)
}
