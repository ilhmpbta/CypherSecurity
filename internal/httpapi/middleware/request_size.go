package middleware

import (
	"errors"
	"net/http"
)

// MaxBodyBytes caps incoming request bodies.
func MaxBodyBytes(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, n)
			next.ServeHTTP(w, r)
		})
	}
}

// CheckMaxBytesError checks if an error is a MaxBytesError and responds with 413 if so.
func CheckMaxBytesError(w http.ResponseWriter, err error) bool {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_, _ = w.Write([]byte(`{"error":"request entity too large"}`))
		return true
	}
	return false
}
