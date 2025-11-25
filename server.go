package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

type Server struct {
	addr string
}

func NewServer(addr string) *Server {
	return &Server{
		addr: addr,
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", s.handleHome)
	mux.HandleFunc("/hello", s.handleHello)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/EndCmd", s.handleEndCmd)

	log.Printf("Starting server on %s", s.addr)
	return http.ListenAndServe(s.addr, mux)
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL.Path)
	fmt.Fprintf(w, "Welcome to Go HTTP Server!\n")
}

func (s *Server) handleHello(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL.Path)
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "World"
	}

	fmt.Fprintf(w, "Hello, %s!\n", name)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL.Path)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK\n")
}

func (s *Server) handleEndCmd(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL.Path)

	if r.URL.Query().Has("darkangel") {
		log.Println("Shutdown command received: /EndCmd?darkangel detected")
		log.Println("Shutting down server...")
		fmt.Fprintf(w, "Server is shutting down...\n")
		go func() {
			os.Exit(0)
		}()
		return
	}

	fmt.Fprintf(w, "EndCmd endpoint - use ?darkangel to shutdown\n")
}
