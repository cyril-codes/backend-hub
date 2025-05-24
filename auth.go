package main

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

type AuthStore interface {
	Login(*LoginInput) (*User, error)
	Register(*RegisterInput) error
	Refresh() error
	Logout() error
	AddSession(string, int, time.Time, time.Time) error
}

type Store struct {
	db *sql.DB
}

type hashParams struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

const (
	createUserTableQuery = `CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
	email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);`
	createSessionsTableQuery = `CREATE TABLE IF NOT EXISTS sessions (
	id TEXT NOT NULL UNIQUE,
	user_id INTEGER NOT NULL,
	issued_at TIMESTAMP NOT NULL,
	expires_at TIMESTAMP NOT NULL,
	revoked_at TIMESTAMP
);`
	registerUserQuery  = `INSERT INTO users(name, email, password_hash) VALUES(?, ?, ?)`
	findUserQuery      = `SELECT * FROM users WHERE email = ?`
	findAllUsersQuery  = `SELECT * FROM users`
	addNewSessionQuery = `INSERT INTO sessions(id, user_id, issued_at, expires_at) VALUES (?, ?, ?, ?);`
)

func InitStore() (*Store, error) {
	db, err := sql.Open("sqlite", "db/auth.db")

	if err != nil {
		return nil, fmt.Errorf("could not open connection to users db\n %+v", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("could not connect to db\n %+v", err)
	}

	_, err = db.Exec(createUserTableQuery)

	if err != nil {
		return nil, fmt.Errorf("could not execute user table query\n %+v", err)
	}

	_, err = db.Exec(createSessionsTableQuery)

	if err != nil {
		return nil, fmt.Errorf("could not execute session table query\n %+v", err)
	}

	log.Println("Connected to DB with table users and sessions")

	return &Store{
		db: db,
	}, nil
}

func (store *Store) Login(login *LoginInput) (*User, error) {
	u, err := getOneUser(store, login.Email)

	if err == sql.ErrNoRows {
		return nil, errors.New("user does not exist")
	}

	p, salt, hash, err := decodeHash(u.PasswordHash)
	if err != nil {
		return nil, err
	}

	otherHash := argon2.IDKey([]byte(login.Password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	if subtle.ConstantTimeCompare(hash, otherHash) == 0 {
		return nil, errors.New("invalid password")
	}

	return u, nil
}

func (store *Store) Register(user *RegisterInput) error {
	err := validateUniqueUser(store, user.Email)
	if err != nil {
		return err
	}

	p := defaultHashParams()

	encodedHash, err := generateHashFromPwd(p, user.Password)
	if err != nil {
		return err
	}

	_, err = store.db.Exec(registerUserQuery, user.Name, user.Email, encodedHash)
	if err != nil {
		return err
	}

	return nil
}

func (store *Store) Refresh() error {
	return nil
}

func (store *Store) Logout() error {
	return nil
}

func (store *Store) AddSession(sessionID string, userID int, issuedAt, expiresAt time.Time) error {
	_, err := store.db.Exec(addNewSessionQuery, sessionID, userID, issuedAt, expiresAt)
	if err != nil {
		return err
	}

	return nil
}

func defaultHashParams() *hashParams {
	return &hashParams{
		memory:      64 * 1024,
		iterations:  3,
		parallelism: 2,
		saltLength:  16,
		keyLength:   32,
	}
}

func validateUniqueUser(store *Store, email string) error {
	u, err := getOneUser(store, email)

	if err == nil && u.Email == email {
		return errors.New("user already registered")
	}

	if err != nil && err != sql.ErrNoRows {
		return errors.New("error verifying user")
	}

	return nil
}

func getOneUser(store *Store, email string) (*User, error) {
	row := store.db.QueryRow(findUserQuery, email)

	u := &User{}
	err := row.Scan(&u.ID, &u.Name, &u.Email, &u.PasswordHash, &u.CreatedAt)

	if err != nil {
		return nil, err
	}

	return u, nil
}

func generateSalt(length uint32) ([]byte, error) {
	buf := make([]byte, length)
	_, err := rand.Read(buf)

	if err != nil {
		return nil, err
	}

	return buf, nil
}

func generateHashFromPwd(params *hashParams, password string) (string, error) {
	salt, err := generateSalt(params.saltLength)
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
		return nil, nil, nil, errors.New("invalid hash format")
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)

	if err != nil {
		return nil, nil, nil, err
	}

	if version != argon2.Version {
		return nil, nil, nil, errors.New("incompatible argon2 version")
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
