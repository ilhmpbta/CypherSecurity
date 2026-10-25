package auth

// Session Timeout Documentation:
// - The two-tier 30m idle + 8h absolute timeout model from the design plan is not fully implemented on the current schema.
// - Sessions have a fixed lifetime of 30 minutes from creation (`expires_at = created_at + 30m`), which is not rolling.
// - Implementing a true rolling idle timeout requires a `last_seen_at` column and a `SessionRepo.Touch` method, which are deferred.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
)

var (
	ErrSessionExpired  = errors.New("session expired")
	ErrSessionNotFound = errors.New("session not found")
)

const sessionDuration = 30 * time.Minute

// SessionStoreOption configures SessionStore.
type SessionStoreOption func(*SessionStore)

// WithSessionClock sets a custom clock function for SessionStore.
func WithSessionClock(clock func() time.Time) SessionStoreOption {
	return func(s *SessionStore) {
		s.now = clock
	}
}

// SessionStore persists and manages server-side sessions.
type SessionStore struct {
	repo repository.SessionRepo
	now  func() time.Time
}

// NewSessionStore creates a new SessionStore backed by repository.SessionRepo.
func NewSessionStore(repo repository.SessionRepo, opts ...SessionStoreOption) *SessionStore {
	store := &SessionStore{
		repo: repo,
		now:  time.Now,
	}
	for _, opt := range opts {
		opt(store)
	}
	return store
}

func tokenToUUID(tokenStr string) (uuid.UUID, error) {
	raw, err := hex.DecodeString(tokenStr)
	if err != nil {
		return uuid.Nil, errors.New("invalid token format")
	}
	if len(raw) != 32 {
		return uuid.Nil, errors.New("invalid token length")
	}
	sum := sha256.Sum256(raw)
	var id uuid.UUID
	copy(id[:], sum[:16])
	return id, nil
}

// Create generates a 32-byte random token, returns its hex-encoded representation
// to the client, and stores its truncated SHA-256 hash as the session UUID in the database.
// Sets expires_at = now + 30m.
func (s *SessionStore) Create(ctx context.Context, userID uuid.UUID) (string, error) {
	rawToken := make([]byte, 32)
	if _, err := rand.Read(rawToken); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}

	tokenStr := hex.EncodeToString(rawToken)
	sessionID, err := tokenToUUID(tokenStr)
	if err != nil {
		return "", err
	}

	now := s.now()
	sess := repository.Session{
		ID:        sessionID,
		UserID:    userID,
		ExpiresAt: now.Add(sessionDuration),
		CreatedAt: now,
	}

	if err := s.repo.Create(ctx, sess); err != nil {
		return "", fmt.Errorf("store session: %w", err)
	}

	return tokenStr, nil
}

// Lookup retrieves a session by its token. Returns ErrSessionNotFound if missing
// or ErrSessionExpired if expired.
func (s *SessionStore) Lookup(ctx context.Context, tokenStr string) (*repository.Session, error) {
	sessionID, err := tokenToUUID(tokenStr)
	if err != nil {
		return nil, ErrSessionNotFound
	}

	sess, err := s.repo.GetByID(ctx, sessionID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lookup session: %w", err)
	}

	if s.now().After(sess.ExpiresAt) {
		_ = s.repo.Delete(ctx, sessionID)
		return nil, ErrSessionExpired
	}

	return &sess, nil
}

// Delete removes a session by its token.
func (s *SessionStore) Delete(ctx context.Context, tokenStr string) error {
	sessionID, err := tokenToUUID(tokenStr)
	if err != nil {
		return ErrSessionNotFound
	}

	err = s.repo.Delete(ctx, sessionID)
	if errors.Is(err, repository.ErrNotFound) {
		return ErrSessionNotFound
	}
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}

	return nil
}
