package rss

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/net/html"
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

	contentType := res.Header.Get("Content-Type")

	if !strings.Contains(contentType, "utf-8") {
		return fmt.Errorf("invalid encoding")
	}

	reader := http.MaxBytesReader(nil, res.Body, maxResBytes)
	tokenizer := html.NewTokenizer(reader)

	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			fmt.Println("Error in reading token")
			return fmt.Errorf("error while reading html content")
		}

		if tt == html.StartTagToken {
			name, _ := tokenizer.TagName()

			if string(name) == "link" {
				key, val, more := tokenizer.TagAttr()

				if string(key) == "rel" && string(val) == "alternate" {
					next := more
					for next {
						key, val, more := tokenizer.TagAttr()
						if string(key) == "href" {
							fmt.Println(string(val))
							next = false
							return nil
						}

						next = more
					}
				}
			}
		}
	}
}
