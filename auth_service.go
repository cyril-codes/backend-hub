package main

import (
	"database/sql"
	"fmt"
	"log"
)

type AuthStore interface {
	Login() error
	Register() error
	Refresh() error
	Logout() error
}

type SqliteDB struct {
	db *sql.DB
}

func InitDB() (*SqliteDB, error) {
	db, err := sql.Open("sqlite", "db/users.db")

	if err != nil {
		return nil, fmt.Errorf("could not open connection to users db\n %+v", err)
	}

	defer db.Close()

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("could not connect to dbs\n %+v", err)
	}

	query := `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	_, err = db.Exec(query)

	if err != nil {
		return nil, fmt.Errorf("could not execute query\n %+v", err)
	}

	log.Println("Connected to DB with table users")

	return &SqliteDB{
		db: db,
	}, nil
}

func (db *SqliteDB) Login() error {
	return nil
}

func (db *SqliteDB) Register() error {
	return nil
}

func (db *SqliteDB) Refresh() error {
	return nil
}

func (db *SqliteDB) Logout() error {
	return nil
}
