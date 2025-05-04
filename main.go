package main

import "log"

func main() {
	db, err := InitDB()
	if err != nil {
		log.Fatal(err)
	}

	s := NewServer(":3000", db)
	s.Run()
}
