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
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

// Build-time injected constants via -ldflags -X
var (
	Version   string
	GitCommit string
	BuildDate string
)

var (
	runEmbedded bool
	seedDB      bool
	dropAll     bool
)

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
	flag.BoolVar(&seedDB, "seed", true, "seed the database with a default admin client and superuser")
	flag.BoolVar(&dropAll, "drop-all", false, "WARNING: drop all data")
	flag.Parse()
}

func main() {
	config.LoadConfig()
	config.Current.Database.SeedDB = seedDB
	config.Current.Database.DropAll = dropAll

	// Setup database
	var db database.Database
	var adminClient *model.ClientInfo
	if runEmbedded {
		badgerDB, err := database.NewBadgerDB(false, nil)
		if err != nil {
			log.Fatalf("Error initializing DB: %v\n", err)
		}
		db = badgerDB
		adminClient = badgerDB.AdminClient
	} else {
		ctx := context.Background()
		var err error
		db, err = database.NewDgraphDatabase(ctx, nil)
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
	r.Use(handlers.CompressHandler)
	r.Use(fthttp.SuppressReferrer)
	r.Use(requestLogger)

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

func requestLogger(next http.Handler) http.Handler {
	return handlers.LoggingHandler(log.Writer(), next)
}
