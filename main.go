package main

import "log"

func main() {
	store, err := InitStore()
	if err != nil {
		log.Fatal(err)
	}

	defer store.db.Close()

	s, err := NewServer(":3000", store)
	if err != nil {
		log.Fatal(err)
	}
	s.Run()
}
