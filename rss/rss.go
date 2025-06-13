package rss

import (
	"database/sql"
	"fmt"
)

type RssService interface {
	AddFeed(url string) error
}

type Store struct {
	DB *sql.DB
}

const maxResBytes = 256 * 1024

func NewStore() (*Store, error) {
	return &Store{
		DB: nil,
	}, nil
}

func (s *Store) AddFeed(input string) error {
	if len(input) == 0 {
		return fmt.Errorf("no url")
	}

	url, err := normalizeUrl(input)
	if err != nil {
		fmt.Printf("Error: %+v\n", err)
		return fmt.Errorf("invalid url")
	}

	if isSafe := isHostSafe(url.Hostname()); !isSafe {
		return fmt.Errorf("invalid url")
	}

	client := newSafeHttpClient()
	res, err := client.Get(url.String())
	if err != nil {
		fmt.Printf("An error happened while querying the input url: %+v\n", err)
		return err
	}

	defer res.Body.Close()

	// reader := http.MaxBytesReader(nil, res.Body, maxResBytes)
	// tokenizer := html.NewTokenizer(reader)

	return nil
}
