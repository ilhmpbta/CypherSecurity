package auth

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeSessionRepo struct {
	mu       sync.Mutex
	sessions map[uuid.UUID]repository.Session
}

func newFakeSessionRepo() *fakeSessionRepo {
	return &fakeSessionRepo{sessions: make(map[uuid.UUID]repository.Session)}
}

func (r *fakeSessionRepo) Create(ctx context.Context, s repository.Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[s.ID] = s
	return nil
}

func (r *fakeSessionRepo) GetByID(ctx context.Context, id uuid.UUID) (repository.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, exists := r.sessions[id]
	if !exists {
		return repository.Session{}, repository.ErrNotFound
	}
	return s, nil
}

func (r *fakeSessionRepo) Delete(ctx context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.sessions[id]; !exists {
		return repository.ErrNotFound
	}
	delete(r.sessions, id)
	return nil
}

func (r *fakeSessionRepo) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var count int64
	for id, s := range r.sessions {
		if s.ExpiresAt.Before(before) {
			delete(r.sessions, id)
			count++
		}
	}
	return count, nil
}

func TestSessionStoreCreateAndLookup(t *testing.T) {
	repo := newFakeSessionRepo()
	currentTime := time.Now()
	store := NewSessionStore(repo, WithSessionClock(func() time.Time { return currentTime }))

	userID := uuid.New()
	token, err := store.Create(context.Background(), userID)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// Baseline Lookup at T+0
	sess0, err := store.Lookup(context.Background(), token)
	assert.NoError(t, err)
	assert.NotNil(t, sess0)
	assert.Equal(t, userID, sess0.UserID)

	// Accepted at T+29m59s
	currentTime = currentTime.Add(29*time.Minute + 59*time.Second)
	sess, err := store.Lookup(context.Background(), token)
	assert.NoError(t, err)
	assert.NotNil(t, sess)
	assert.Equal(t, userID, sess.UserID)

	// Rejected at T+30m1s (Rolling idle behavior is out of scope; fixed lifetime expiry test)
	currentTime = currentTime.Add(2 * time.Second)
	sess, err = store.Lookup(context.Background(), token)
	assert.ErrorIs(t, err, ErrSessionExpired)
	assert.Nil(t, sess)
}

func TestSessionStoreDelete(t *testing.T) {
	repo := newFakeSessionRepo()
	store := NewSessionStore(repo)

	userID := uuid.New()
	token, err := store.Create(context.Background(), userID)
	require.NoError(t, err)

	err = store.Delete(context.Background(), token)
	assert.NoError(t, err)

	sess, err := store.Lookup(context.Background(), token)
	assert.ErrorIs(t, err, ErrSessionNotFound)
	assert.Nil(t, sess)
}
