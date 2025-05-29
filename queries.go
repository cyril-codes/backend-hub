package main

import (
	"database/sql"
	"fmt"
	"time"
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

/*
	TODO: Setup all methods to all be associated to store.db instead of being a mixed bag between function receivers and having the store as parameter
	TODO: Setup all queries to be defined and used here specifically instead of calling them elsewhere
*/

func getOneUser(store *Store, email string) (*User, error) {
	row := store.db.QueryRow(findUserQuery, email)

	u := &User{}
	err := row.Scan(&u.ID, &u.Name, &u.Email, &u.PasswordHash, &u.CreatedAt)

	if err != nil {
		return nil, err
	}

	return u, nil
}

func createTable(db *sql.DB, query string) error {
	_, err := db.Exec(query)

	if err != nil {
		return fmt.Errorf("could not execute user table query\n %+v", err)
	}

	return nil
}

func (store *Store) AddSession(sessionID, userID string, issuedAt, expiresAt time.Time) error {
	_, err := store.db.Exec(addNewSessionQuery, sessionID, userID, issuedAt, expiresAt)
	if err != nil {
		return err
	}

	return nil
}

type Session struct {
	ID        string     `db:"id"`
	userID    string     `db:"user_id"`
	issuedAt  time.Time  `db:"issued_at"`
	expiresAt time.Time  `db:"expires_at"`
	revokedAt *time.Time `db:"revoked_at"`
}

func (store *Store) FindSession(sessionId string) (*Session, error) {
	row := store.db.QueryRow(findSessionQuery, sessionId)

	s := &Session{}
	err := row.Scan(&s.ID, &s.userID, &s.issuedAt, &s.expiresAt, &s.revokedAt)
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (store *Store) RevokeSession(sessionId string) error {
	_, err := store.db.Exec(updateRevokationQuery, time.Now(), sessionId)

	if err != nil {
		return err
	}

	return nil
}
