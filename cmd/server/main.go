package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
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
	fthttp "github.com/ftauth/ftauth/pkg/http"
	"github.com/ftauth/ftauth/pkg/model"
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
	var adminClient *model.ClientInfo
	if runEmbedded {
		opts := database.BadgerOptions{
			Path:   config.Current.Database.Dir,
			SeedDB: true,
		}
		badgerDB, err := database.InitializeBadgerDB(opts)
		if err != nil {
			log.Fatalf("Error initializing DB: %v\n", err)
		}
		db = badgerDB
		adminClient = badgerDB.AdminClient
	} else {
		opts := database.DgraphOptions{
			URL:      config.Current.Database.URL,
			APIKey:   config.Current.Database.APIKey,
			Username: config.Current.Database.Username,
			Password: config.Current.Database.Password,
			SeedDB:   true,
		}

		ctx := context.Background()
		var err error
		db, err = database.InitializeDgraphDatabase(ctx, opts)
		if err != nil {
			log.Fatalln("Error initializing DB: ", err)
		}

		ctx, cancel := context.WithTimeout(ctx, database.DefaultTimeout)
		defer cancel()

		adminClient, _ = db.GetDefaultAdminClient(ctx)
	}

	// Print out the admin client
	adminJSON, err := json.MarshalIndent(adminClient, "", "  ")
	if err != nil {
		log.Fatalln("Error marshalling admin client: ", err)
	}
	fmt.Printf("Admin client: %s\n", adminJSON)

	// Setup routing
	r := mux.NewRouter()
	auth.SetupRoutes(r, db, db, db)
	discovery.SetupRoutes(r, db)
	admin.SetupRoutes(r, db, db)
	user.SetupRoutes(r, db)

	err = templates.SetupTemplates(staticFS)
	if err != nil {
		log.Fatalln("Error parsing templates: ", err)
	}
	// Index handler
	r.Path("/").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := templates.All.ExecuteTemplate(w, "login", config.Current.Server)
		if err != nil {
			log.Printf("Error templating index: %v\n", err)
		}
	})

	// Health check handler
	r.Path("/ok").Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	// Static file handling
	stripped, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalln(err)
	}
	r.PathPrefix("/").Handler(http.FileServer(http.FS(stripped)))

	// Apply middleware
	r.Use(fthttp.SuppressReferrer)

	addr := ":" + config.Current.Server.Port
	srv := http.Server{
		Addr:    addr,
		Handler: r,

		ReadHeaderTimeout: 30 * time.Second,
		WriteTimeout:      60 * time.Second,
	}

	go func() {
		if config.Current.Server.UseTLS() {
			log.Printf("Listening on https://localhost%s\n", addr)
			log.Fatal(srv.ListenAndServeTLS(
				config.Current.Server.TLS.ServerCertFile,
				config.Current.Server.TLS.ServerKeyFile,
			))
		} else {
			log.Printf("Listening on http://localhost%s\n", addr)
			log.Fatal(srv.ListenAndServe())
		}
	}()

	c := make(chan os.Signal, 1)
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
