package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/ftauth/ftauth/internal/admin"
	"github.com/ftauth/ftauth/internal/auth"
	"github.com/ftauth/ftauth/internal/config"
	"github.com/ftauth/ftauth/internal/database"
	"github.com/ftauth/ftauth/internal/discovery"
	"github.com/ftauth/ftauth/internal/templates"
	"github.com/ftauth/ftauth/internal/user"
	"github.com/gorilla/mux"
)

// Build-time injected constants via -ldflags -X
var (
	Version   string
	GitCommit string
	BuildDate string
)

var runEmbedded bool

// staticFS holds static files for the web server like
// templates and global CSS styles
//go:embed static
var staticFS embed.FS

func init() {
	var version string
	if Version != "" {
		version = Version
	} else if buildInfo, ok := debug.ReadBuildInfo(); ok {
		version = buildInfo.Main.Version
	} else {
		version = "Unknown"
	}
	fmt.Println("Version:\t", version)

	fmt.Println("Git commit:\t", GitCommit)
	fmt.Println("Build date:\t", BuildDate)

	flag.BoolVar(&runEmbedded, "embedded", false, "run in embedded mode")
	flag.Parse()
}

func main() {
	config.LoadConfig()

	// Setup database
	var db database.Database
	if runEmbedded {
		opts := database.Options{
			Path:   config.Current.Database.Dir,
			SeedDB: true,
		}
		badgerDB, err := database.InitializeBadgerDB(opts)
		if err != nil {
			log.Fatalf("Error initializing DB: %v\n", err)
		}
		db = badgerDB
		adminClient := badgerDB.AdminClient

		adminJSON, err := json.Marshal(adminClient)
		if err != nil {
			log.Fatalln("Error marshalling admin client: ", err)
		}
		fmt.Printf("Admin client: %s\n", adminJSON)
	} else {
		_, err := database.InitializeDgraphDatabase()
		if err != nil {
			log.Fatalln("Error initializing DB: ", err)
		}
		// TODO: db = dgraphDB
	}
	// Setup routing
	r := mux.NewRouter()
	auth.SetupRoutes(r, db, db, db)
	discovery.SetupRoutes(r, db)
	admin.SetupRoutes(r, db)
	user.SetupRoutes(r)

	err := templates.SetupTemplates(staticFS)
	if err != nil {
		log.Fatalln("Error parsing templates: ", err)
	}

	// Static file handling
	r.PathPrefix("/").Handler(http.FileServer(http.FS(staticFS)))

	// Apply middleware
	r.Use(auth.SuppressReferrer)

	addr := ":" + config.Current.Server.Port
	srv := http.Server{
		Addr:    addr,
		Handler: r,

		ReadHeaderTimeout: 30 * time.Second,
		WriteTimeout:      60 * time.Second,
	}

	go func() {
		log.Printf("Listening on localhost%s\n", addr)
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
