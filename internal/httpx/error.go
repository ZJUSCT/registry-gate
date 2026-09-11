// Package httpx contains shared HTTP plumbing for registry-gate: the
// registry error schema, client-IP extraction honoring trusted proxies,
// request logging middleware, an in-memory sliding-window rate limiter
// and a dependency-free Prometheus-style metrics endpoint.
package httpx

import (
	"encoding/json"
	"net/http"
)

// WriteError emits a Docker registry v2 error body so that docker/podman
// surface the message on the terminal:
//
//	{"errors":[{"code":"<code>","message":"<message>"}]}
func WriteError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Errors are small; ignore write failures (client gone).
	_ = json.NewEncoder(w).Encode(struct {
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}{
		Errors: []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}{{Code: code, Message: message}},
	})
}
