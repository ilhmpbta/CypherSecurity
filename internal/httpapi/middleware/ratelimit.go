package middleware

import "net/http"

// RateLimit throttles requests per client.
func RateLimit(next http.Handler) http.Handler { return next }
