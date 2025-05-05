package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"

	_ "modernc.org/sqlite"
)

const emailRegexp = `[\w\d.\-_]{2,63}@[\w\d.-]+.\w{2,5}`

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
	user := new(LoginInput)

	err := json.NewDecoder(req.Body).Decode(user)

	if err != nil {
		return WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	err = s.store.Login(user)

	if err != nil {
		return WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	return WriteJSON(w, http.StatusOK, "well done")
}

func (s *Server) handleRegister(w http.ResponseWriter, req *http.Request) error {
	user := new(RegisterInput)

	err := json.NewDecoder(req.Body).Decode(user)
	if err != nil {
		return WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	if err := verifyUser(user); err != nil {
		return WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	err = s.store.Register(user)
	if err != nil {
		return WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	// TODO: Do not return user and change status code
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

func verifyUser(u *RegisterInput) error {
	if len(u.Name) < 3 {
		return errors.New("name is too short")
	}

	if pLength := len(u.Password); pLength < 12 || pLength > 64 {
		return errors.New("invalid password length")
	}

	if len(u.Email) > 254 {
		return errors.New("invalid email length")
	}

	if match, _ := regexp.MatchString(emailRegexp, u.Email); !match {
		return errors.New("invalid email content")
	}

	return nil
}
