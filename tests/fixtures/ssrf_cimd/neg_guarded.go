package auth

import (
	"errors"
	"net"
	"net/http"
	"syscall"
)

func safeClient() *http.Client {
	d := &net.Dialer{Control: func(network, address string, c syscall.RawConn) error {
		host, _, _ := net.SplitHostPort(address)
		ip := net.ParseIP(host)
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return errors.New("blocked")
		}
		return nil
	}}
	return &http.Client{
		Transport:     &http.Transport{DialContext: d.DialContext},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func FetchClientMetadata(clientID string) (*http.Response, error) {
	return safeClient().Get(clientID)
}
