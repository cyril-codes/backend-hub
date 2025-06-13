package main

import (
	"log"

	"github.com/cyril-codes/backend-hub/auth"
	"github.com/cyril-codes/backend-hub/rss"
)

func main() {
	auth, err := auth.NewStore()
	if err != nil {
		log.Fatal(err)
	}

	rss, err := rss.NewStore()
	if err != nil {
		log.Fatal(err)
	}

	defer auth.DB.Close()
	defer rss.DB.Close()

	s, err := NewServer(":3000", auth, rss)
	if err != nil {
		log.Fatal(err)
	}
	s.Run()
}
