package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/cyril-codes/backend-hub/auth"
	_ "modernc.org/sqlite"
)

var emptyCookie = &http.Cookie{
	Name:     "refresh_token",
	Value:    "",
	Path:     "/",
	HttpOnly: true,
	Secure:   true,
	Expires:  time.Unix(0, 0),
	MaxAge:   0,
	SameSite: http.SameSiteStrictMode,
}

type Server struct {
	listenAddr string
	store      auth.AuthService
}

func NewServer(addr string, store auth.AuthService) (*Server, error) {
	return &Server{
		listenAddr: addr,
		store:      store,
	}, nil
}

func (s *Server) Run() {
	http.HandleFunc("POST /login", makeHttpHandler(s.handleLogin))
	http.HandleFunc("POST /register", makeHttpHandler(s.handleRegister))
	http.HandleFunc("POST /refresh", makeHttpHandler(s.handleRefresh))
	http.HandleFunc("POST /logout", makeHttpHandler(s.handleLogout))

	log.Println("Server starting on port", s.listenAddr)
	if err := http.ListenAndServe(s.listenAddr, nil); err != nil {
		log.Fatal(err)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, req *http.Request) error {
	userInput := new(auth.LoginInput)

	err := json.NewDecoder(req.Body).Decode(userInput)

	if err != nil {
		return WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	meta, err := s.store.Login(userInput)
	if err != nil {
		return WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	http.SetCookie(w, meta.Cookie)

	response := auth.LoginResponse{
		User:        meta.Name,
		AccessToken: meta.AccessToken,
	}
	return WriteJSON(w, http.StatusOK, response)
}

func (s *Server) handleRegister(w http.ResponseWriter, req *http.Request) error {
	user := new(auth.RegisterInput)

	err := json.NewDecoder(req.Body).Decode(user)
	if err != nil {
		return WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	err = s.store.Register(user)
	if err != nil {
		return WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	return WriteJSON(w, http.StatusCreated, nil)
}

func (s *Server) handleRefresh(w http.ResponseWriter, req *http.Request) error {
	cookie, err := req.Cookie("refresh_token")
	if err != nil {
		http.SetCookie(w, emptyCookie)
		return WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	meta, err := s.store.Refresh(cookie)
	if err != nil {
		http.SetCookie(w, emptyCookie)
		return WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	http.SetCookie(w, meta.Cookie)
	response := auth.RefreshResponse{
		AccessToken: meta.AccessToken,
	}

	return WriteJSON(w, http.StatusOK, response)
}

func (s *Server) handleLogout(w http.ResponseWriter, req *http.Request) error {
	cookie, err := req.Cookie("refresh_token")
	http.SetCookie(w, emptyCookie)

	if err != nil {
		return WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	if err := s.store.Logout(cookie); err != nil {
		return WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	return WriteJSON(w, http.StatusNoContent, nil)
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

	if v == nil {
		return nil
	}

	return json.NewEncoder(w).Encode(v)
}
