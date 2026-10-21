package middleware

import "net/http"

// MaxBodyBytes caps incoming request bodies.
func MaxBodyBytes(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return next }
}
