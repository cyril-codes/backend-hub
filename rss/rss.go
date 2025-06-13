package rss

import (
	"database/sql"
	"fmt"
	"net/url"
)

type RssService interface {
	AddFeed(url string) error
}

type Store struct {
	DB *sql.DB
}

func NewStore() (*Store, error) {
	return &Store{
		DB: nil,
	}, nil
}

func (s *Store) AddFeed(input string) error {
	if len(input) == 0 {
		return fmt.Errorf("no url")
	}

	url, err := url.Parse(input)
	if err != nil {
		return fmt.Errorf("invalid url")
	}

	fmt.Println("url ", url)

	return nil
}
