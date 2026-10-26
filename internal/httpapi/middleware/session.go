package middleware

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
)

type contextKey int

const (
	sessionKey contextKey = iota
	userKey
)

type SessionStore interface {
	Lookup(ctx context.Context, token string) (*repository.Session, error)
}

type UserRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (repository.User, error)
}

// Session authenticates requests using the server-side session store.
func Session(sessionStore SessionStore, userRepo UserRepo) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("session_id")
			if err != nil || cookie.Value == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
				return
			}

			sess, err := sessionStore.Lookup(r.Context(), cookie.Value)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
				return
			}

			user, err := userRepo.GetByID(r.Context(), sess.UserID)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
				return
			}

			ctx := context.WithValue(r.Context(), sessionKey, sess)
			ctx = context.WithValue(ctx, userKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// UserFromContext extracts the authenticated user from the context.
func UserFromContext(ctx context.Context) (*repository.User, bool) {
	u, ok := ctx.Value(userKey).(repository.User)
	if ok {
		return &u, true
	}
	ptr, ok := ctx.Value(userKey).(*repository.User)
	return ptr, ok
}

// SessionFromContext extracts the session from the context.
func SessionFromContext(ctx context.Context) (*repository.Session, bool) {
	s, ok := ctx.Value(sessionKey).(*repository.Session)
	return s, ok
}
