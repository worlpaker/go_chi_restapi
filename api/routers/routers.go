package routers

import (
	_ "backend/api/docs"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
	httpSwagger "github.com/swaggo/http-swagger/v2"
)

// Handlers to route server
func (s *Server) SetupRouters() {
	// Middlewares
	s.Router.Use(
		middleware.RequestID,
		middleware.RealIP,
		middleware.Logger,
		middleware.Recoverer,
		render.SetContentType(render.ContentTypeJSON),
		MiddlewareLang,
	)
	s.Router.Get("/", s.Handlers.Home)
	s.Router.Post("/register", s.Handlers.Register)
	s.Router.Post("/login", s.Handlers.Login)
	s.Router.Get("/info/{nickname}", s.Handlers.BioPublic)
	// Usersonly Handlers
	s.Router.Mount("/profile", s.UserRouters())

	// documentation
	s.Router.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL("http://localhost:8000/swagger/doc.json"), //The url pointing to API definition
	))
}

// UserHandlers routes only users
func (s *Server) UserRouters() chi.Router {
	r := chi.NewRouter()
	r.Use(UsersOnly)
	r.Get("/", s.Handlers.Profile)
	// user info(bio)
	r.Post("/info", s.Handlers.AddBio)
	r.Put("/info", s.Handlers.EditBio)
	r.Delete("/info", s.Handlers.DeleteBio)

	r.Post("/logout", s.Handlers.Logout)

	return r
}
