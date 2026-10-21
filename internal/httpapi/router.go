package httpapi

import "net/http"

// NewRouter returns the root HTTP handler.
func NewRouter() http.Handler {
	return http.NewServeMux()
}
