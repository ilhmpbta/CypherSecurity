package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
)

// CSRF enforces token checks on state-changing requests.
func CSRF(secureCookies bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Ensure csrf_token cookie exists on every response
			cookie, err := r.Cookie("csrf_token")
			var token string
			if err != nil || cookie.Value == "" {
				randomBytes := make([]byte, 32)
				if _, err := rand.Read(randomBytes); err == nil {
					token = hex.EncodeToString(randomBytes)
					http.SetCookie(w, &http.Cookie{
						Name:     "csrf_token",
						Value:    token,
						Path:     "/",
						HttpOnly: false,
						SameSite: http.SameSiteLaxMode,
						Secure:   secureCookies,
					})
				}
			} else {
				token = cookie.Value
			}

			// For non-GET requests, require X-CSRF-Token header matching cookie
			if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
				headerToken := r.Header.Get("X-CSRF-Token")
				if headerToken == "" || token == "" || subtle.ConstantTimeCompare([]byte(headerToken), []byte(token)) != 1 {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`{"error":"csrf token invalid"}`))
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
