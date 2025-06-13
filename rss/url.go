package rss

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

func isHostSafe(host string) bool {
	ips, err := net.LookupIP(host)
	if err != nil {
		return false
	}

	for _, ip := range ips {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return false
		}
	}
	return true
}

func newSafeHttpClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}

			if !isValidScheme(req.URL.Scheme) {
				return fmt.Errorf("invalid scheme")
			}

			if !isHostSafe(req.URL.Hostname()) {
				return fmt.Errorf("host is not safe")
			}

			return nil
		},
	}
}

func normalizeUrl(input string) (*url.URL, error) {
	url, err := url.Parse(input)
	if err != nil {
		return nil, err
	}

	if !isValidScheme(url.Scheme) {
		return nil, fmt.Errorf("invalid scheme")
	}

	if url.Scheme == "" {
		url, _ = url.Parse("http://" + input)
	}

	return url, nil
}

func isValidScheme(scheme string) bool {
	return scheme == "" || scheme == "http" || scheme == "https"
}
