package main

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

const emailRegexp = `[\w\d.\-_]{2,63}@[\w\d.-]+.\w{2,5}`

type jwtKeys struct {
	private *rsa.PrivateKey
	public  *rsa.PublicKey
}

type Server struct {
	listenAddr string
	store      AuthStore
	jwt        jwtKeys
}

type LoginResponse struct {
	User        string `json:"user"`
	AccessToken string `json:"accessToken"`
}

type RefreshResponse struct {
	AccessToken string `json:"accessToken"`
}

type HttpHandlerFunc func(http.ResponseWriter, *http.Request) error

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

func NewServer(addr string, store AuthStore) (*Server, error) {
	privateKey, err := os.ReadFile("jwt/jwtRS256.key")
	if err != nil {
		return nil, fmt.Errorf("could not open private key file\n %+v", err)
	}

	publicKey, err := os.ReadFile("jwt/jwtRS256.key.pub")
	if err != nil {
		return nil, fmt.Errorf("could not open public key file\n %+v", err)
	}

	private, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("could not parse private key\n %+v", err)
	}

	public, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return nil, fmt.Errorf("could not parse public key\n %+v", err)
	}

	return &Server{
		listenAddr: addr,
		store:      store,
		jwt: jwtKeys{
			private: private,
			public:  public,
		},
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
	userInput := new(LoginInput)

	err := json.NewDecoder(req.Body).Decode(userInput)

	if err != nil {
		return WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	user, err := s.store.Login(userInput)

	if err != nil {
		return WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	issuedAt := time.Now()

	accessToken, err := s.makeAccessToken(user.ID, issuedAt)
	if err != nil {
		return WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	refreshToken, err := s.makeAndStoreRefreshToken(user.ID, issuedAt)
	if err != nil {
		return WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	cookie := http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		Expires:  issuedAt.Add(time.Hour * 72),
		MaxAge:   60 * 60 * 72,
		SameSite: http.SameSiteStrictMode,
	}

	http.SetCookie(w, &cookie)

	response := LoginResponse{
		User:        user.Name,
		AccessToken: accessToken,
	}

	return WriteJSON(w, http.StatusOK, response)
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

	return WriteJSON(w, http.StatusCreated, nil)
}

func (s *Server) handleRefresh(w http.ResponseWriter, req *http.Request) error {
	cookie, err := req.Cookie("refresh_token")
	if err != nil {
		http.SetCookie(w, emptyCookie)
		return WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	token, err := jwt.ParseWithClaims(cookie.Value, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return s.jwt.public, nil
	})

	if token == nil || !token.Valid {
		http.SetCookie(w, emptyCookie)
		return WriteJSON(w, http.StatusBadRequest, "invalid token")
	}

	if err != nil {
		http.SetCookie(w, emptyCookie)
		return WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		http.SetCookie(w, emptyCookie)
		return WriteJSON(w, http.StatusBadRequest, "cannot extract claims from token")
	}

	now := time.Now().Add(time.Second * 30)

	if now.Compare(claims.IssuedAt.Time) != 1 {
		http.SetCookie(w, emptyCookie)
		return WriteJSON(w, http.StatusBadRequest, "token issued in the future")
	}

	if now.Compare(claims.ExpiresAt.Time) != -1 {
		http.SetCookie(w, emptyCookie)
		return WriteJSON(w, http.StatusBadRequest, "token expired")
	}

	session, err := s.store.FindSession(claims.ID)
	if err != nil {
		http.SetCookie(w, emptyCookie)
		return WriteJSON(w, http.StatusBadRequest, "cannot find session")
	}

	if session.revokedAt != nil {
		http.SetCookie(w, emptyCookie)
		return WriteJSON(w, http.StatusBadRequest, "session has been revoked")
	}

	if session.userID != claims.Subject {
		http.SetCookie(w, emptyCookie)
		return WriteJSON(w, http.StatusBadRequest, "incorrect user")
	}

	err = s.store.RevokeSession(session.ID)
	if err != nil {
		return WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	iat := time.Now()
	accessToken, err := s.makeAccessToken(claims.Subject, iat)
	if err != nil {
		return WriteJSON(w, http.StatusBadRequest, "cannot issue access token")
	}

	refreshToken, err := s.makeAndStoreRefreshToken(claims.Subject, iat)
	if err != nil {
		return WriteJSON(w, http.StatusBadRequest, "cannot issue refresh token")
	}

	newCookie := http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		Expires:  iat.Add(time.Hour * 72),
		MaxAge:   60 * 60 * 72,
		SameSite: http.SameSiteStrictMode,
	}

	http.SetCookie(w, &newCookie)

	response := RefreshResponse{
		AccessToken: accessToken,
	}

	return WriteJSON(w, http.StatusOK, response)
}

func (s *Server) handleLogout(w http.ResponseWriter, req *http.Request) error {
	cookie, err := req.Cookie("refresh_token")
	if err != nil {
		http.SetCookie(w, emptyCookie)
		return WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	token, err := jwt.ParseWithClaims(cookie.Value, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return s.jwt.public, nil
	})

	if token == nil || !token.Valid {
		http.SetCookie(w, emptyCookie)
		return WriteJSON(w, http.StatusBadRequest, "invalid token")
	}

	if err != nil {
		http.SetCookie(w, emptyCookie)
		return WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		http.SetCookie(w, emptyCookie)
		return WriteJSON(w, http.StatusBadRequest, "cannot extract claims from token")
	}

	now := time.Now().Add(time.Second * 30)

	if now.Compare(claims.IssuedAt.Time) != 1 {
		http.SetCookie(w, emptyCookie)
		return WriteJSON(w, http.StatusBadRequest, "token issued in the future")
	}

	if now.Compare(claims.ExpiresAt.Time) != -1 {
		http.SetCookie(w, emptyCookie)
		return WriteJSON(w, http.StatusBadRequest, "token expired")
	}

	session, err := s.store.FindSession(claims.ID)
	if err != nil {
		http.SetCookie(w, emptyCookie)
		return WriteJSON(w, http.StatusBadRequest, "cannot find session")
	}

	if session.revokedAt != nil {
		http.SetCookie(w, emptyCookie)
		return WriteJSON(w, http.StatusBadRequest, "session has been revoked")
	}

	if session.userID != claims.Subject {
		http.SetCookie(w, emptyCookie)
		return WriteJSON(w, http.StatusBadRequest, "incorrect user")
	}

	err = s.store.RevokeSession(session.ID)
	if err != nil {
		return WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	http.SetCookie(w, emptyCookie)
	return WriteJSON(w, http.StatusNoContent, nil)
}

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

	if status == http.StatusNoContent {
		return nil
	}

	return json.NewEncoder(w).Encode(v)
}

func (s *Server) makeAccessToken(id string, issuedAt time.Time) (string, error) {
	expiry := issuedAt.Add(time.Minute * 30)

	claims := &jwt.RegisteredClaims{
		Subject:   id,
		IssuedAt:  jwt.NewNumericDate(issuedAt),
		ExpiresAt: jwt.NewNumericDate(expiry),
	}

	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	return t.SignedString(s.jwt.private)
}

// TODO: Split make and store logic
func (s *Server) makeAndStoreRefreshToken(id string, issuedAt time.Time) (string, error) {
	sessionId := uuid.NewString()
	expiry := issuedAt.Add(time.Hour * 72)

	claims := &jwt.RegisteredClaims{
		Subject:   id,
		IssuedAt:  jwt.NewNumericDate(issuedAt),
		ExpiresAt: jwt.NewNumericDate(expiry),
		ID:        sessionId,
	}

	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	if err := s.store.AddSession(sessionId, id, issuedAt, expiry); err != nil {
		return "", err
	}

	return t.SignedString(s.jwt.private)
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
