package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dnys1/ftoauth/internal/admin"
	"github.com/dnys1/ftoauth/internal/auth"
	"github.com/dnys1/ftoauth/internal/config"
	"github.com/dnys1/ftoauth/internal/database"
	"github.com/dnys1/ftoauth/internal/discovery"
	"github.com/dnys1/ftoauth/internal/model"
	"github.com/gorilla/mux"
)

func main() {
	config.LoadConfig()

	// Setup database
	db := database.InitializePostgresDB()
	sqlDB := &database.SQLDatabase{Type: model.DatabaseTypePostgres, DB: db}

	// Setup routing
	r := mux.NewRouter()
	auth.SetupRoutes(r, sqlDB, sqlDB)
	discovery.SetupRoutes(r, sqlDB)
	admin.SetupRoutes(r)

	// Static file handling
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("template")))

	addr := fmt.Sprintf("%s:%s", config.Current.Server.Host, config.Current.Server.Port)
	srv := http.Server{
		Addr:    addr,
		Handler: r,

		ReadHeaderTimeout: 30 * time.Second,
		WriteTimeout:      60 * time.Second,
	}

	go func() {
		log.Printf("Listening on %s\n", addr)
		log.Fatal(srv.ListenAndServe())
	}()

	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	<-c

	err := srv.Close()
	if err != nil {
		log.Printf("Error shutting down server: %v\n", err)
	}

	err = db.Close()
	if err != nil {
		log.Printf("Error closing database: %v\n", err)
	}
}
