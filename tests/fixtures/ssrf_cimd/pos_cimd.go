package auth

import (
	"encoding/json"
	"net/http"
)

func FetchClientMetadata(clientID string) (map[string]any, error) {
	resp, err := http.Get(clientID)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var m map[string]any
	return m, json.NewDecoder(resp.Body).Decode(&m)
}

func Discover(issuer string) (*http.Response, error) {
	u := issuer + "/.well-known/openid-configuration"
	return http.Get(u)
}
