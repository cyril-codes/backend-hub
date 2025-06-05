package main

import (
	"log"

	"github.com/cyril-codes/backend-hub/auth"
)

func main() {
	store, err := auth.NewStore()
	if err != nil {
		log.Fatal(err)
	}

	defer store.DB.Close()

	s, err := NewServer(":3000", store)
	if err != nil {
		log.Fatal(err)
	}
	s.Run()
}
