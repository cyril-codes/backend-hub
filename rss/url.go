package rss

import (
	"fmt"
	"net"
	"net/http"
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

			if !isHostSafe(req.URL.Hostname()) {
				return fmt.Errorf("host is not safe")
			}

			return nil
		},
	}
}
