// Minimal excerpt (struct declaration + the ServeHTTP method's own signature
// and opening body) reproduced under the MIT/Apache-2.0-transition license
// from modelcontextprotocol/go-sdk, mcp/streamable.go, commit
// d836ceb87d0424dd64bd08061b3f88dfc31bbe59
// (https://github.com/modelcontextprotocol/go-sdk).
//
// Reproduced here as a real-world regression fixture for mcp-safeguard's
// entrypoints_go.py shape F, `interface_method_override` (see
// bench/SDK_VOCAB_AND_TRUNCATION_FIX_STATUS.md section 2.2). This is the
// real CVE-2026-33252 shape: `StreamableHTTPHandler.ServeHTTP` is a raw
// `http.Handler` interface override that shapes A-E have no vocabulary for
// (it is the transport layer invoking tool handlers, not a tool handler
// itself) -- before this fix, this file appeared in zero evidence packs for
// any hunter angle.
package mcp

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// A StreamableHTTPHandler is an http.Handler that serves streamable MCP
// sessions, as defined by the MCP spec.
type StreamableHTTPHandler struct {
	getServer func(*http.Request) *Server
	opts      StreamableHTTPOptions

	onTransportDeletion func(sessionID string) // for testing

	mu       sync.Mutex
	sessions map[string]*sessionInfo // keyed by session ID
}

func (h *StreamableHTTPHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// DNS rebinding protection: auto-enabled for localhost servers.
	if !h.opts.DisableLocalhostProtection && disablelocalhostprotection != "1" {
		if localAddr, ok := req.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && localAddr != nil {
			if util.IsLoopback(localAddr.String()) && !util.IsLoopback(req.Host) {
				http.Error(w, fmt.Sprintf("Forbidden: invalid Host header %q", req.Host), http.StatusForbidden)
				return
			}
		}
	}

	// Allow multiple 'Accept' headers.
	accept := strings.Split(strings.Join(req.Header.Values("Accept"), ","), ",")
	var jsonOK, streamOK bool
	for _, c := range accept {
		switch strings.TrimSpace(c) {
		case "application/json", "application/*":
			jsonOK = true
		case "text/event-stream", "text/*":
			streamOK = true
		}
	}
}
