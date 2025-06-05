package auth

import (
	"time"

	"github.com/google/uuid"
)

const (
	createUserTableQuery = `CREATE TABLE IF NOT EXISTS users (
  id TEXT NOT NULL PRIMARY KEY,
  name TEXT NOT NULL,
	email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);`
	createSessionsTableQuery = `CREATE TABLE IF NOT EXISTS sessions (
	id TEXT NOT NULL UNIQUE,
	user_id TEXT NOT NULL,
	issued_at TIMESTAMP NOT NULL,
	expires_at TIMESTAMP NOT NULL,
	revoked_at TIMESTAMP
);`
	registerUserQuery     = `INSERT INTO users(id, name, email, password_hash) VALUES(?, ?, ?, ?);`
	findUserQuery         = `SELECT * FROM users WHERE email = ?;`
	addNewSessionQuery    = `INSERT INTO sessions(id, user_id, issued_at, expires_at) VALUES (?, ?, ?, ?);`
	findSessionQuery      = `SELECT * FROM sessions WHERE id = ?;`
	updateRevokationQuery = `UPDATE sessions SET revoked_at = ? WHERE id = ?;`
)

func (store *Store) getOneUser(email string) (*User, error) {
	row := store.DB.QueryRow(findUserQuery, email)

	u := &User{}
	if err := row.Scan(&u.ID, &u.Name, &u.Email, &u.PasswordHash, &u.CreatedAt); err != nil {
		return nil, err
	}

	return u, nil
}

func (store *Store) registerUser(name, email, pwd string) error {
	id := uuid.NewString()
	if _, err := store.DB.Exec(registerUserQuery, id, name, email, pwd); err != nil {
		return err
	}

	return nil
}

func (store *Store) createTable(query string) error {
	if _, err := store.DB.Exec(query); err != nil {
		return err
	}

	return nil
}

func (store *Store) addSession(sessionID, userID string, issuedAt, expiresAt time.Time) error {
	if _, err := store.DB.Exec(addNewSessionQuery, sessionID, userID, issuedAt, expiresAt); err != nil {
		return err
	}

	return nil
}

func (store *Store) findSession(sessionId string) (*Session, error) {
	row := store.DB.QueryRow(findSessionQuery, sessionId)

	s := &Session{}
	if err := row.Scan(&s.ID, &s.userID, &s.issuedAt, &s.expiresAt, &s.revokedAt); err != nil {
		return nil, err
	}

	return s, nil
}

func (store *Store) revokeSession(sessionId string) error {
	if _, err := store.DB.Exec(updateRevokationQuery, time.Now(), sessionId); err != nil {
		return err
	}

	return nil
}
