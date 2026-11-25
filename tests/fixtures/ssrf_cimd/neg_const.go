package auth

import "net/http"

func Ping() (*http.Response, error) {
	return http.Get("https://example.com/status")
}
