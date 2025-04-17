package api

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/sikozonpc/ecom/services/cart"
	"github.com/sikozonpc/ecom/services/order"
	"github.com/sikozonpc/ecom/services/product"
	"github.com/sikozonpc/ecom/services/user"
)

type APIServer struct {
	addr string
	db   *sql.DB
}

func NewAPIServer(addr string, db *sql.DB) *APIServer {
	return &APIServer{
		addr: addr,
		db:   db,
	}
}

// Run starts the API server and listens for incoming requests
// It uses the gorilla/mux router to handle routing.
// The server listens on the address specified in the addr field.
// It registers the routes for the user, product, and order services.
// It also serves static files from the "static" directory.
// The server uses the http.ListenAndServe function to start the server.
// The server will block until it is stopped or an error occurs.
func (s *APIServer) Run() error {
	router := mux.NewRouter()
	subrouter := router.PathPrefix("/api/v1").Subrouter()

	userStore := user.NewStore(s.db)
	userHandler := user.NewHandler(userStore)
	userHandler.RegisterRoutes(subrouter)
	// TODO: Stopped right here
	productStore := product.NewStore(s.db)
	productHandler := product.NewHandler(productStore, userStore)
	productHandler.RegisterRoutes(subrouter)

	orderStore := order.NewStore(s.db)

	cartHandler := cart.NewHandler(productStore, orderStore, userStore)
	cartHandler.RegisterRoutes(subrouter)

	// Serve static files
	router.PathPrefix("/").Handler(http.FileServer(http.Dir("static")))

	log.Println("Listening on", s.addr)

	return http.ListenAndServe(s.addr, router)
}
