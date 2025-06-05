package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	httperror "github.com/cyril-codes/backend-hub/httpError"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

var (
	defaultHashParams = hashParams{
		memory:      64 * 1024,
		iterations:  3,
		parallelism: 2,
		saltLength:  16,
		keyLength:   32,
	}
	ErrDBConnectionFailure      = errors.New("could not connect to db")
	ErrJWTKeyFailure            = errors.New("could not find or parse key")
	ErrInvalidPassword          = errors.New("invalid password")
	ErrExistingUser             = errors.New("user already registered")
	ErrInvalidHash              = errors.New("invalid hash")
	ErrIncompatibleArgonVersion = errors.New("incompatible argon2 version")
	ErrInvalidName              = errors.New("invalid name")
	ErrInvalidEmail             = errors.New("invalid email")
	ErrInvalidLogin             = errors.New("invalid email or password")
	ErrInvalidToken             = errors.New("invalid or expired token")
	ErrInternalLogin            = errors.New("an error occured while trying to login")
	ErrInternalRegister         = errors.New("an error occured while trying to register")
	ErrInternalRefresh          = errors.New("an error occured while trying to refresh tokens")
)

const emailRegexp = `[\w\d.\-_]{2,63}@[\w\d.-]+.\w{2,5}`

func NewStore() (*Store, error) {
	db, err := sql.Open("sqlite", "db/auth.db")

	if err != nil {
		return nil, ErrDBConnectionFailure
	}

	if err := db.Ping(); err != nil {
		return nil, ErrDBConnectionFailure
	}

	privateKey, err := os.ReadFile("jwt/jwtRS256.key")
	if err != nil {
		return nil, ErrJWTKeyFailure
	}

	publicKey, err := os.ReadFile("jwt/jwtRS256.key.pub")
	if err != nil {
		return nil, ErrJWTKeyFailure
	}

	private, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil, ErrJWTKeyFailure
	}

	public, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return nil, ErrJWTKeyFailure
	}

	store := &Store{
		DB: db,
		jwt: jwtKeys{
			private: private,
			public:  public,
		},
	}

	err = store.createTable(createUserTableQuery)
	if err != nil {
		return nil, err
	}

	err = store.createTable(createSessionsTableQuery)
	if err != nil {
		return nil, err
	}

	log.Println("Connected to DB with table users and sessions")

	return store, nil
}

func (store *Store) Login(login *LoginInput) (*LoginMeta, *httperror.HttpError) {
	u, err := store.getOneUser(login.Email)

	if err == sql.ErrNoRows {
		return nil, httperror.Unauthorized(ErrInvalidLogin)
	}

	p, salt, hash, err := decodeHash(u.PasswordHash)
	if err != nil {
		return nil, httperror.InternalError(ErrInternalLogin)
	}

	otherHash := argon2.IDKey([]byte(login.Password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	if subtle.ConstantTimeCompare(hash, otherHash) == 0 {
		return nil, httperror.Unauthorized(ErrInvalidLogin)
	}

	iat := time.Now()

	accessToken, err := store.newAccessToken(u.ID, iat)
	if err != nil {
		return nil, httperror.InternalError(ErrInternalLogin)
	}

	refreshToken, err := store.newRefreshToken(u.ID, iat)
	if err != nil {
		return nil, httperror.InternalError(ErrInternalLogin)
	}

	cookie := newRefreshCookie(refreshToken, iat.Add(time.Hour*72))

	return &LoginMeta{Name: u.Name, AccessToken: accessToken, Cookie: cookie}, nil
}

func (store *Store) Register(user *RegisterInput) *httperror.HttpError {
	if err := validateUserInput(user); err != nil {
		return httperror.BadRequest(err)
	}

	if err := store.validateUniqueUser(user.Email); err != nil {
		if errors.Is(err, ErrExistingUser) {
			return httperror.Conflict(err)
		}

		return httperror.InternalError(ErrInternalRegister)
	}

	encodedHash, err := newHashedPassword(&defaultHashParams, user.Password)
	if err != nil {
		return httperror.InternalError(ErrInternalRegister)
	}

	if err := store.registerUser(user.Name, user.Email, encodedHash); err != nil {
		return httperror.InternalError(ErrInternalRegister)
	}

	return nil
}

func (store *Store) Refresh(cookie *http.Cookie) (*RefreshMeta, *httperror.HttpError) {
	token, err := jwt.ParseWithClaims(cookie.Value, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return store.jwt.public, nil
	})

	if err != nil || token == nil || !token.Valid {
		return nil, httperror.Unauthorized(ErrInvalidToken)
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return nil, httperror.Unauthorized(ErrInvalidToken)
	}

	iat := time.Now()
	comp := iat.Add(time.Second * 30)

	if comp.Compare(claims.IssuedAt.Time) != 1 {
		return nil, httperror.Unauthorized(ErrInvalidToken)
	}

	if comp.Compare(claims.ExpiresAt.Time) != -1 {
		return nil, httperror.Unauthorized(ErrInvalidToken)
	}

	session, err := store.findSession(claims.ID)
	if err != nil {
		return nil, httperror.Unauthorized(ErrInvalidToken)
	}

	if session.revokedAt != nil {
		return nil, httperror.Unauthorized(ErrInvalidToken)
	}

	if session.userID != claims.Subject {
		return nil, httperror.Unauthorized(ErrInvalidToken)
	}

	if err := store.revokeSession(session.ID); err != nil {
		return nil, httperror.InternalError(ErrInternalRefresh)
	}

	accessToken, err := store.newAccessToken(claims.Subject, iat)
	if err != nil {
		return nil, httperror.InternalError(ErrInternalRefresh)
	}

	refreshToken, err := store.newRefreshToken(claims.Subject, iat)
	if err != nil {
		return nil, httperror.InternalError(ErrInternalRefresh)
	}

	cookie = newRefreshCookie(refreshToken, iat.Add(time.Hour*72))
	return &RefreshMeta{AccessToken: accessToken, Cookie: cookie}, nil
}

func (store *Store) Logout(cookie *http.Cookie) *httperror.HttpError {
	token, err := jwt.ParseWithClaims(cookie.Value, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return store.jwt.public, nil
	})

	if token == nil || !token.Valid || err != nil {
		return httperror.Unauthorized(ErrInvalidToken)
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return httperror.Unauthorized(ErrInvalidToken)
	}

	now := time.Now().Add(time.Second * 30)

	if now.Compare(claims.IssuedAt.Time) != 1 {
		return httperror.Unauthorized(ErrInvalidToken)
	}

	if now.Compare(claims.ExpiresAt.Time) != -1 {
		return httperror.Unauthorized(ErrInvalidToken)
	}

	session, err := store.findSession(claims.ID)
	if err != nil {
		return httperror.Unauthorized(ErrInvalidToken)
	}

	if session.revokedAt != nil {
		return httperror.Unauthorized(ErrInvalidToken)
	}

	if session.userID != claims.Subject {
		return httperror.Unauthorized(ErrInvalidToken)
	}

	if err := store.revokeSession(session.ID); err != nil {
		return httperror.InternalError(ErrInternalRefresh)
	}

	return nil
}

func (store *Store) validateUniqueUser(email string) error {
	u, err := store.getOneUser(email)

	if err == nil && u.Email == email {
		return ErrExistingUser
	}

	if err != nil && err != sql.ErrNoRows {
		return err
	}

	return nil
}

func (store *Store) newAccessToken(id string, issuedAt time.Time) (string, error) {
	expiry := issuedAt.Add(time.Minute * 30)

	claims := &jwt.RegisteredClaims{
		Subject:   id,
		IssuedAt:  jwt.NewNumericDate(issuedAt),
		ExpiresAt: jwt.NewNumericDate(expiry),
	}

	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	return t.SignedString(store.jwt.private)
}

func (store *Store) newRefreshToken(id string, issuedAt time.Time) (string, error) {
	sessionId := uuid.NewString()
	expiry := issuedAt.Add(time.Hour * 72)

	claims := &jwt.RegisteredClaims{
		Subject:   id,
		IssuedAt:  jwt.NewNumericDate(issuedAt),
		ExpiresAt: jwt.NewNumericDate(expiry),
		ID:        sessionId,
	}

	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	if err := store.addSession(sessionId, id, issuedAt, expiry); err != nil {
		return "", err
	}

	return t.SignedString(store.jwt.private)
}

func newSalt(length uint32) ([]byte, error) {
	buf := make([]byte, length)
	_, err := rand.Read(buf)

	if err != nil {
		return nil, err
	}

	return buf, nil
}

func newHashedPassword(params *hashParams, password string) (string, error) {
	salt, err := newSalt(params.saltLength)
	if err != nil {
		return "", err
	}

	pwd := argon2.IDKey([]byte(password), salt, params.iterations, params.memory, params.parallelism, params.keyLength)

	b64Pwd := base64.RawStdEncoding.EncodeToString(pwd)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)

	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, params.memory, params.iterations, params.parallelism, b64Salt, b64Pwd)

	return encodedHash, nil
}

func decodeHash(encodedHash string) (p *hashParams, salt, hash []byte, err error) {
	vals := strings.Split(encodedHash, "$")

	if len(vals) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)

	if err != nil {
		return nil, nil, nil, err
	}

	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleArgonVersion
	}

	p = &hashParams{}

	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.memory, &p.iterations, &p.parallelism)

	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}

	p.saltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, err
	}

	p.keyLength = uint32(len(hash))

	return p, salt, hash, nil
}

func newRefreshCookie(token string, exp time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     "refresh_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		Expires:  exp,
		MaxAge:   60 * 60 * 72,
		SameSite: http.SameSiteStrictMode,
	}
}

func validateUserInput(u *RegisterInput) error {
	if len(u.Name) < 3 {
		return ErrInvalidName
	}

	if pLength := len(u.Password); pLength < 12 || pLength > 64 {
		return ErrInvalidPassword
	}

	if len(u.Email) > 254 {
		return ErrInvalidEmail
	}

	if match, _ := regexp.MatchString(emailRegexp, u.Email); !match {
		return ErrInvalidEmail
	}

	return nil
}
