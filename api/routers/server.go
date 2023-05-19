package routers

import (
	"backend/api/handlers"

	"github.com/go-chi/chi"
)

type Server struct {
	Router   *chi.Mux
	Handlers *handlers.Server
}
