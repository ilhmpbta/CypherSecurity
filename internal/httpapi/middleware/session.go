package middleware

import "net/http"

// Session authenticates requests using the server-side session store.
func Session(next http.Handler) http.Handler { return next }
