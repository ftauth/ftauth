package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ftauth/ftauth/internal/admin"
	"github.com/ftauth/ftauth/internal/auth"
	"github.com/ftauth/ftauth/internal/config"
	"github.com/ftauth/ftauth/internal/database"
	"github.com/ftauth/ftauth/internal/discovery"
	"github.com/ftauth/ftauth/internal/user"
	"github.com/gorilla/mux"
)

// Build-time injected constants via -ldflags -X
var (
	Version   string
	GitCommit string
	BuildDate string
)

func init() {
	fmt.Println("Version:\t", Version)
	fmt.Println("Git commit:\t", GitCommit)
	fmt.Println("Build date:\t", BuildDate)
}

func main() {
	config.LoadConfig()

	// Setup database
	opts := database.Options{
		Path:   config.Current.Database.Dir,
		SeedDB: true,
	}
	db, err := database.InitializeBadgerDB(opts)
	if err != nil {
		log.Fatalf("Error initializing DB: %v\n", err)
	}
	adminClient := db.AdminClient

	fmt.Printf("Admin client: %#v\n", adminClient)

	// Setup routing
	r := mux.NewRouter()
	auth.SetupRoutes(r, db, db, db)
	discovery.SetupRoutes(r, db)
	admin.SetupRoutes(r, db)
	user.SetupRoutes(r)

	// Static file handling
	templateDir := config.Current.OAuth.Template.Options.Dir
	r.PathPrefix("/").Handler(http.FileServer(http.Dir(templateDir)))

	addr := fmt.Sprintf("%s:%d", "localhost", config.Current.Server.Port)
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

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = srv.Shutdown(ctx)
	if err != nil {
		log.Printf("Error shutting down server: %v\n", err)
	}

	log.Println("Closing database connection...")
	err = db.Close()
	if err != nil {
		log.Printf("Error closing database: %v\n", err)
	}
}
