package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		fmt.Fprintf(w, "Got params\nCode: %s\nState: %s", code, state)
	}).Methods(http.MethodOptions, http.MethodGet)

	srv := &http.Server{
		Addr:    ":8081",
		Handler: r,
	}

	go log.Fatal(srv.ListenAndServe())

	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)

	<-c

	srv.Close()
}
