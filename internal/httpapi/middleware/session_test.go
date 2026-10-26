package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
	"github.com/stretchr/testify/assert"
)

type fakeSessionStore struct {
	sess *repository.Session
	err  error
}

func (f *fakeSessionStore) Lookup(ctx context.Context, token string) (*repository.Session, error) {
	return f.sess, f.err
}

type fakeUserRepo struct {
	user repository.User
	err  error
}

func (f *fakeUserRepo) GetByID(ctx context.Context, id uuid.UUID) (repository.User, error) {
	return f.user, f.err
}

func TestSessionMiddleware(t *testing.T) {
	userID := uuid.New()
	user := repository.User{ID: userID, Username: "testuser", CreatedAt: time.Now()}
	sess := &repository.Session{ID: uuid.New(), UserID: userID, ExpiresAt: time.Now().Add(time.Hour)}

	store := &fakeSessionStore{sess: sess}
	uRepo := &fakeUserRepo{user: user}

	handler := Session(store, uRepo)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := UserFromContext(r.Context())
		assert.True(t, ok)
		assert.Equal(t, user.Username, u.Username)
		w.WriteHeader(http.StatusOK)
	}))

	// Test missing session cookie
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// Test valid session cookie
	req = httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "validtoken"})
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}
