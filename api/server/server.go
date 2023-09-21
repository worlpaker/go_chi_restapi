package server

import (
	"backend/api/handlers"
	"backend/api/routers"
	"backend/config"
	"backend/database"
	"backend/database/pqdb"
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
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
			DB: &database.DB{
				Postgres: &pqdb.Server{
					Client: db,
				},
			},
		},
	}
	return s
}

// gracefulShutDown gracefully shuts down the HTTP server.
func gracefulShutDown(serverStopCh <-chan os.Signal, server *http.Server) {
	<-serverStopCh
	log.Println("Shutting down the server...")
	// Create a context with a timeout to allow existing connections to finish
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Shutdown the server gracefully
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Error during server shutdown: %v\n", err)
	}
	log.Println("Server gracefully shut down")
}

// Start an HTTP server with the provided server configuration.
func Start() {
	r, d := NewAuth()
	s := NewServer(r, d)
	s.SetupRouters()

	server := &http.Server{
		Addr:    config.ServerPort,
		Handler: s.Router,
	}

	// Create a channel to listen for OS signals
	serverStopCh := make(chan os.Signal, 1)
	signal.Notify(serverStopCh, syscall.SIGINT, syscall.SIGTERM)

	// Start the server in a separate goroutine
	go func() {
		log.Println("Server is listening on", config.ServerPort)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Error: %v\n", err)
		}
	}()
	gracefulShutDown(serverStopCh, server)
}
