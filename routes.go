package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/cyril-codes/backend-hub/auth"
	"github.com/cyril-codes/backend-hub/rss"
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

const (
	invalidInput  = "invalid input"
	invalidToken  = "invalid or expired token"
	refreshCookie = "refresh_token"
)

type Server struct {
	listenAddr string
	auth       auth.AuthService
	rss        rss.RssService
}

func NewServer(addr string, auth auth.AuthService, rss rss.RssService) (*Server, error) {
	return &Server{
		listenAddr: addr,
		auth:       auth,
		rss:        rss,
	}, nil
}

func (s *Server) Run() {
	http.HandleFunc("POST /login", makeHttpHandler(s.handleLogin))
	http.HandleFunc("POST /register", makeHttpHandler(s.handleRegister))
	http.HandleFunc("POST /refresh", makeHttpHandler(s.handleRefresh))
	http.HandleFunc("POST /logout", makeHttpHandler(s.handleLogout))
	http.HandleFunc("POST /feeds", makeHttpHandler(s.handleAddRSS))

	log.Println("Server starting on port", s.listenAddr)
	if err := http.ListenAndServe(s.listenAddr, nil); err != nil {
		log.Fatal(err)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, req *http.Request) error {
	userInput := new(auth.LoginInput)

	err := json.NewDecoder(req.Body).Decode(userInput)
	if err != nil {
		return WriteJSON(w, http.StatusBadRequest, invalidInput)
	}

	meta, httpErr := s.auth.Login(userInput)
	if httpErr != nil {
		return WriteJSON(w, httpErr.Code, httpErr.Error())
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

	httpErr := s.auth.Register(user)
	if httpErr != nil {
		return WriteJSON(w, httpErr.Code, httpErr.Error())
	}

	return WriteJSON(w, http.StatusCreated, nil)
}

func (s *Server) handleRefresh(w http.ResponseWriter, req *http.Request) error {
	cookie, err := req.Cookie(refreshCookie)
	if err != nil {
		http.SetCookie(w, emptyCookie)
		return WriteJSON(w, http.StatusUnauthorized, invalidToken)
	}

	meta, httpErr := s.auth.Refresh(cookie)
	if httpErr != nil {
		http.SetCookie(w, emptyCookie)
		return WriteJSON(w, httpErr.Code, httpErr.Error())
	}

	http.SetCookie(w, meta.Cookie)
	response := auth.RefreshResponse{
		AccessToken: meta.AccessToken,
	}

	return WriteJSON(w, http.StatusOK, response)
}

func (s *Server) handleLogout(w http.ResponseWriter, req *http.Request) error {
	cookie, err := req.Cookie(refreshCookie)
	http.SetCookie(w, emptyCookie)

	if err != nil {

		return WriteJSON(w, http.StatusUnauthorized, invalidToken)
	}

	if httpErr := s.auth.Logout(cookie); httpErr != nil {
		return WriteJSON(w, httpErr.Code, httpErr.Error())
	}

	return WriteJSON(w, http.StatusNoContent, nil)
}

type Input struct {
	Url string `json:"url"`
}

func (s *Server) handleAddRSS(w http.ResponseWriter, req *http.Request) error {
	if isValid := s.auth.IsAuthorized(req); !isValid {
		return WriteJSON(w, http.StatusUnauthorized, "invalid token")
	}

	var input Input
	err := json.NewDecoder(req.Body).Decode(&input)
	if err != nil {
		return WriteJSON(w, http.StatusUnauthorized, "invalid token")
	}

	if err := s.rss.AddFeed(input.Url); err != nil {
		return WriteJSON(w, http.StatusUnauthorized, "invalid url")
	}

	return WriteJSON(w, http.StatusOK, "Nice")
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
