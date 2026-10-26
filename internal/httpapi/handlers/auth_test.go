package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
	"github.com/stretchr/testify/assert"
)

type fakeAuthService struct {
	registerFn func(ctx context.Context, username, password string) (repository.User, error)
	loginFn    func(ctx context.Context, username, password, ip string) (string, error)
	logoutFn   func(ctx context.Context, token string) error
}

func (f *fakeAuthService) Register(ctx context.Context, u, p string) (repository.User, error) {
	if f.registerFn != nil {
		return f.registerFn(ctx, u, p)
	}
	return repository.User{}, nil
}
func (f *fakeAuthService) Login(ctx context.Context, u, p, ip string) (string, error) {
	if f.loginFn != nil {
		return f.loginFn(ctx, u, p, ip)
	}
	return "", nil
}
func (f *fakeAuthService) Logout(ctx context.Context, token string) error {
	if f.logoutFn != nil {
		return f.logoutFn(ctx, token)
	}
	return nil
}

type fakeUserRepoForAuth struct {
	user repository.User
	err  error
}

func (f *fakeUserRepoForAuth) GetByUsername(ctx context.Context, username string) (repository.User, error) {
	return f.user, f.err
}
func (f *fakeUserRepoForAuth) GetByID(ctx context.Context, id uuid.UUID) (repository.User, error) {
	return f.user, f.err
}
func (f *fakeUserRepoForAuth) Create(ctx context.Context, u, h string) (repository.User, error) {
	return repository.User{}, nil
}

func TestAuthRegisterMalformedJSON(t *testing.T) {
	svc := &fakeAuthService{}
	uRepo := &fakeUserRepoForAuth{}
	h := NewAuthHandler(svc, uRepo, true)

	req := httptest.NewRequest("POST", "/api/auth/register", strings.NewReader("{malformed"))
	rec := httptest.NewRecorder()
	h.Register(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "error")
	assert.NotContains(t, rec.Body.String(), "sql")
	assert.NotContains(t, rec.Body.String(), "stack")
}

func TestAuthRegisterSuccess(t *testing.T) {
	userID := uuid.New()
	svc := &fakeAuthService{
		registerFn: func(ctx context.Context, u, p string) (repository.User, error) {
			return repository.User{ID: userID, Username: u, CreatedAt: time.Now()}, nil
		},
	}
	uRepo := &fakeUserRepoForAuth{}
	h := NewAuthHandler(svc, uRepo, true)

	req := httptest.NewRequest("POST", "/api/auth/register", strings.NewReader(`{"username":"alice","password":"secretpassword"}`))
	rec := httptest.NewRecorder()
	h.Register(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Contains(t, rec.Body.String(), "alice")
}
