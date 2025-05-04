package main

import (
	"encoding/json"
	"log"
	"net/http"

	_ "modernc.org/sqlite"
)

type Server struct {
	listenAddr string
	store      AuthStore
}

func NewServer(addr string, store AuthStore) *Server {
	return &Server{
		listenAddr: addr,
		store:      store,
	}
}

func (s *Server) Run() {
	http.HandleFunc("POST /login", makeHttpHandler(s.handleLogin))
	http.HandleFunc("POST /register", makeHttpHandler(s.handleRegister))

	log.Println("Server starting on port", s.listenAddr)
	if err := http.ListenAndServe(s.listenAddr, nil); err != nil {
		log.Fatal(err)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, req *http.Request) error {
	return nil
}

func (s *Server) handleRegister(w http.ResponseWriter, req *http.Request) error {
	user := new(User)
	err := json.NewDecoder(req.Body).Decode(user)

	if err != nil {
		return WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	return WriteJSON(w, http.StatusOK, user)
}

func (s *Server) handleRefresh(w http.ResponseWriter, req *http.Request) error {
	return nil
}

func (s *Server) handleLogout(w http.ResponseWriter, req *http.Request) error {
	return nil
}

type HttpHandlerFunc func(http.ResponseWriter, *http.Request) error

func makeHttpHandler(f HttpHandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			WriteJSON(w, http.StatusBadRequest, err.Error())
		}
	}
}

func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)

	return json.NewEncoder(w).Encode(v)
}
