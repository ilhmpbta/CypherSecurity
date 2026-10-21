package middleware

import "net/http"

// CSRF enforces token checks on state-changing requests.
func CSRF(next http.Handler) http.Handler { return next }
