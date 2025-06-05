package auth

import (
	"crypto/rsa"
	"database/sql"
	"net/http"
	"time"

	httperror "github.com/cyril-codes/backend-hub/httpError"
)

type AuthService interface {
	Login(*LoginInput) (*LoginMeta, *httperror.HttpError)
	Register(*RegisterInput) *httperror.HttpError
	Refresh(*http.Cookie) (*RefreshMeta, *httperror.HttpError)
	Logout(*http.Cookie) *httperror.HttpError
}

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

type Store struct {
	DB  *sql.DB
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

type LoginResponse struct {
	User        string `json:"user"`
	AccessToken string `json:"accessToken"`
}

type RefreshResponse struct {
	AccessToken string `json:"accessToken"`
}
