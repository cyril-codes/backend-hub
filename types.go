package main

import "time"

type User struct {
	ID           int
	Name         string
	PasswordHash string
	CreatedAt    time.Time
}
