package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeUserRepo struct {
	mu    sync.Mutex
	users map[string]repository.User
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{users: make(map[string]repository.User)}
}

func (r *fakeUserRepo) Create(ctx context.Context, username, passwordHash string) (repository.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.users[username]; exists {
		return repository.User{}, repository.ErrConflict
	}
	u := repository.User{
		ID:           uuid.New(),
		Username:     username,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now(),
	}
	r.users[username] = u
	return u, nil
}

func (r *fakeUserRepo) GetByUsername(ctx context.Context, username string) (repository.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, exists := r.users[username]
	if !exists {
		return repository.User{}, repository.ErrNotFound
	}
	return u, nil
}

func (r *fakeUserRepo) GetByID(ctx context.Context, id uuid.UUID) (repository.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range r.users {
		if u.ID == id {
			return u, nil
		}
	}
	return repository.User{}, repository.ErrNotFound
}

func TestRegisterAndLogin(t *testing.T) {
	userRepo := newFakeUserRepo()
	sessionRepo := newFakeSessionRepo()
	sessionStore := NewSessionStore(sessionRepo)
	svc := NewService(userRepo, sessionStore)

	ctx := context.Background()

	// Register
	user, err := svc.Register(ctx, "alice", "SecurePass123!")
	require.NoError(t, err)
	assert.Equal(t, "alice", user.Username)

	// Duplicate registration -> ErrUsernameTaken
	_, err = svc.Register(ctx, "alice", "OtherPass123!")
	assert.ErrorIs(t, err, ErrUsernameTaken)

	// Successful login
	token, err := svc.Login(ctx, "alice", "SecurePass123!", "127.0.0.1")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Logout
	err = svc.Logout(ctx, token)
	assert.NoError(t, err)
}

func TestLoginEnumerationEquivalence(t *testing.T) {
	userRepo := newFakeUserRepo()
	sessionRepo := newFakeSessionRepo()
	sessionStore := NewSessionStore(sessionRepo)
	svc := NewService(userRepo, sessionStore)
	ctx := context.Background()

	_, err := svc.Register(ctx, "bob", "Password123!")
	require.NoError(t, err)

	// Wrong password for existing user
	_, err1 := svc.Login(ctx, "bob", "WrongPass123!", "127.0.0.1")

	// Unknown username
	_, err2 := svc.Login(ctx, "charlie", "Password123!", "127.0.0.1")

	assert.ErrorIs(t, err1, ErrInvalidCredentials)
	assert.ErrorIs(t, err2, ErrInvalidCredentials)
	assert.Equal(t, err1, err2)
}

func TestLoginThrottlingAndLockoutExpiry(t *testing.T) {
	userRepo := newFakeUserRepo()
	sessionRepo := newFakeSessionRepo()
	sessionStore := NewSessionStore(sessionRepo)

	currentTime := time.Now()
	svc := NewService(userRepo, sessionStore, WithServiceClock(func() time.Time { return currentTime }))
	ctx := context.Background()

	_, err := svc.Register(ctx, "dave", "Password123!")
	require.NoError(t, err)

	ip := "192.168.1.1"

	// 5 failed attempts
	for i := 0; i < 5; i++ {
		_, err := svc.Login(ctx, "dave", "WrongPass!", ip)
		assert.ErrorIs(t, err, ErrInvalidCredentials)
	}

	// 6th attempt returns ErrThrottled
	_, err = svc.Login(ctx, "dave", "WrongPass!", ip)
	assert.ErrorIs(t, err, ErrThrottled)

	// Correct password during lockout: still throttled — lockout check runs before VerifyPassword.
	_, err = svc.Login(ctx, "dave", "Password123!", ip)
	assert.ErrorIs(t, err, ErrThrottled)

	// Fix 3 Test: Advance clock to T + 60s + 1ns (lockout expired)
	currentTime = currentTime.Add(60*time.Second + 1*time.Nanosecond)

	// Wrong password attempt should return ErrInvalidCredentials (not ErrThrottled)
	_, err = svc.Login(ctx, "dave", "WrongPass!", ip)
	assert.ErrorIs(t, err, ErrInvalidCredentials)

	// Correct password attempt at the same instant returns nil (successful login)
	token, err := svc.Login(ctx, "dave", "Password123!", ip)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestGCThrottleEvictsStaleBuckets(t *testing.T) {
	userRepo := newFakeUserRepo()
	sessionRepo := newFakeSessionRepo()
	sessionStore := NewSessionStore(sessionRepo)

	currentTime := time.Now()
	svc := NewService(userRepo, sessionStore, WithServiceClock(func() time.Time { return currentTime }))
	ctx := context.Background()

	// Create a bucket with failures=3 at T
	staleKey := throttleKey("user1", "1.1.1.1")
	staleBucket := svc.getOrCreateBucket(staleKey)
	staleBucket.mu.Lock()
	staleBucket.failures = 3
	staleBucket.windowStart = currentTime
	staleBucket.mu.Unlock()

	// Advance clock past window duration (T + 2*windowDuration + 1s)
	currentTime = currentTime.Add(2*windowDuration + 1*time.Second)

	// Trigger gcThrottles via svc.Login on an unrelated key
	_, _ = svc.Login(ctx, "nonexistent", "wrong", "2.2.2.2")

	// Assert len(svc.throttles) has dropped the stale bucket
	svc.throttleMu.Lock()
	_, staleExists := svc.throttles[staleKey]
	svc.throttleMu.Unlock()
	assert.False(t, staleExists, "stale bucket should have been evicted by GC")

	// Create a locked bucket whose lockout extends beyond the window,
	// so "window elapsed, lock still active" is reachable.
	lockedKey := throttleKey("user2", "3.3.3.3")
	lockedBucket := svc.getOrCreateBucket(lockedKey)
	lockedBucket.mu.Lock()
	lockedBucket.failures = 5
	lockedBucket.windowStart = currentTime
	lockedBucket.lockedUntil = currentTime.Add(3 * windowDuration) // longer than window
	lockedBucket.mu.Unlock()

	// Advance past window, still inside lockout.
	currentTime = currentTime.Add(windowDuration + windowDuration/2)

	// Trigger GC.
	_, _ = svc.Login(ctx, "nonexistent2", "wrong", "4.4.4.4")

	svc.throttleMu.Lock()
	_, lockedExists := svc.throttles[lockedKey]
	svc.throttleMu.Unlock()
	assert.True(t, lockedExists, "locked bucket with elapsed window must be preserved by GC")

	// Bucket whose lockout has expired.
	expiredKey := throttleKey("user3", "5.5.5.5")
	expiredBucket := svc.getOrCreateBucket(expiredKey)
	expiredBucket.mu.Lock()
	expiredBucket.failures = 5
	expiredBucket.windowStart = currentTime
	expiredBucket.lockedUntil = currentTime.Add(lockoutDuration)
	expiredBucket.mu.Unlock()

	// Advance past lockout expiry.
	currentTime = currentTime.Add(2 * lockoutDuration)

	// Trigger GC.
	_, _ = svc.Login(ctx, "nonexistent3", "wrong", "6.6.6.6")

	svc.throttleMu.Lock()
	_, expiredExists := svc.throttles[expiredKey]
	svc.throttleMu.Unlock()
	assert.False(t, expiredExists, "post-lockout bucket must be evicted (leak fix); preservation must not last forever")
}

func TestParallelLoginThrottle(t *testing.T) {
	userRepo := newFakeUserRepo()
	sessionRepo := newFakeSessionRepo()
	sessionStore := NewSessionStore(sessionRepo)
	svc := NewService(userRepo, sessionStore)
	ctx := context.Background()

	_, err := svc.Register(ctx, "eve", "Password123!")
	require.NoError(t, err)

	ip := "10.0.0.1"
	var wg sync.WaitGroup
	attempts := 10
	errs := make([]error, attempts)

	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := svc.Login(ctx, "eve", "WrongPass!", ip)
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	throttledCount := 0
	invalidCount := 0
	for _, err := range errs {
		if errors.Is(err, ErrThrottled) {
			throttledCount++
		} else if errors.Is(err, ErrInvalidCredentials) {
			invalidCount++
		}
	}

	// Exactly 5 failed attempts should be processed and 5 should be throttled
	assert.Equal(t, 5, invalidCount)
	assert.Equal(t, 5, throttledCount)
}
