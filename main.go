package main

import "log"

func main() {
	db, err := InitDB()
	if err != nil {
		log.Fatal(err)
	}

	defer db.db.Close()

	s := NewServer(":3000", db)
	s.Run()
}
