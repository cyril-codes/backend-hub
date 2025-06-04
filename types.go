package main

import (
	"crypto/rsa"
	"database/sql"
	"net/http"
	"time"
)

type User struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"password"`
	CreatedAt    time.Time `json:"createdAt"`
}

type RegisterInput struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginMeta struct {
	Name        string
	AccessToken string
	Cookie      *http.Cookie
}

type RefreshMeta struct {
	AccessToken string
	Cookie      *http.Cookie
}

type Session struct {
	ID        string     `db:"id"`
	userID    string     `db:"user_id"`
	issuedAt  time.Time  `db:"issued_at"`
	expiresAt time.Time  `db:"expires_at"`
	revokedAt *time.Time `db:"revoked_at"`
}

type AuthStore interface {
	Login(*LoginInput) (*LoginMeta, error)
	Register(*RegisterInput) error
	Refresh(*http.Cookie) (*RefreshMeta, error)
	Logout(*http.Cookie) error
}

type Store struct {
	db  *sql.DB
	jwt jwtKeys
}

type hashParams struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

type jwtKeys struct {
	private *rsa.PrivateKey
	public  *rsa.PublicKey
}

type Server struct {
	listenAddr string
	store      AuthStore
}

type LoginResponse struct {
	User        string `json:"user"`
	AccessToken string `json:"accessToken"`
}

type RefreshResponse struct {
	AccessToken string `json:"accessToken"`
}

type HttpHandlerFunc func(http.ResponseWriter, *http.Request) error
