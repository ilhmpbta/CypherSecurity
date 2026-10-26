package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
)

var (
	ErrUsernameTaken      = errors.New("username already taken")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrThrottled          = errors.New("too many failed login attempts, please try again later")
)

// Login Throttling Configuration:
// - N = 5 failed attempts within a 60-second sliding window.
// - The 5th wrong attempt is allowed to complete (returning ErrInvalidCredentials); the 6th attempt returns ErrThrottled.
// - Lockout duration M = 60 seconds.
// - Successful login clears the throttle bucket for that (username, IP) key.
// - Throttle GC runs opportunistically at the top of Login (evicting expired buckets). No background goroutine.
// - Note: This throttle is per-process; horizontal scaling across multiple instances would require a shared store (out of scope).

const (
	maxFailedAttempts = 5
	windowDuration    = 60 * time.Second
	lockoutDuration   = 60 * time.Second
)

var dummyHash string

// init generates a dummy Argon2id hash at startup (~100ms test-startup cost).
func init() {
	var err error
	dummyHash, err = HashPassword("cyphersecurity-dummy-password-not-used")
	if err != nil {
		panic(fmt.Sprintf("auth: cannot build dummy hash: %v", err))
	}
}

// AuditLogger defines the interface for recording audit events.
type AuditLogger interface {
	Log(ctx context.Context, e repository.AuditEvent) error
}

type throttleBucket struct {
	mu          sync.Mutex
	failures    int
	windowStart time.Time
	lockedUntil time.Time
}

// ServiceOption configures Service.
type ServiceOption func(*Service)

// WithServiceClock sets a custom clock function for Service.
func WithServiceClock(clock func() time.Time) ServiceOption {
	return func(s *Service) {
		s.now = clock
	}
}

type Service struct {
	userRepo     repository.UserRepo
	sessionStore *SessionStore
	auditLogger  AuditLogger
	now          func() time.Time

	throttleMu sync.Mutex
	throttles  map[string]*throttleBucket
}

// NewService instantiates an auth Service.
func NewService(userRepo repository.UserRepo, sessionStore *SessionStore, auditLogger AuditLogger, opts ...ServiceOption) *Service {
	srv := &Service{
		userRepo:     userRepo,
		sessionStore: sessionStore,
		auditLogger:  auditLogger,
		now:          time.Now,
		throttles:    make(map[string]*throttleBucket),
	}
	for _, opt := range opts {
		opt(srv)
	}
	return srv
}

func (s *Service) getOrCreateBucket(key string) *throttleBucket {
	s.throttleMu.Lock()
	defer s.throttleMu.Unlock()
	b, exists := s.throttles[key]
	if !exists {
		b = &throttleBucket{windowStart: s.now()}
		s.throttles[key] = b
	}
	return b
}

func (s *Service) gcThrottles(now time.Time) {
	// Note: GC is best-effort and can briefly orphan an in-flight bucket; accepted limitation for this ticket.
	s.throttleMu.Lock()
	defer s.throttleMu.Unlock()
	for k, b := range s.throttles {
		b.mu.Lock()
		// Evict buckets whose sliding window has elapsed and whose lockout (if any) has expired.
		// Evicting such a bucket is behaviorally identical to the window-reset branch in Login, so no rate-limit state is lost.
		// Buckets currently locked out must be preserved -- eviction would reset the lockout.
		stale := now.Sub(b.windowStart) >= windowDuration &&
			(b.lockedUntil.IsZero() || now.After(b.lockedUntil))
		b.mu.Unlock()
		if stale {
			delete(s.throttles, k)
		}
	}
}

func throttleKey(username, ip string) string {
	// NUL separator prevents collisions when username contains '|'.
	sum := sha256.Sum256([]byte(username + "\x00" + ip))
	return hex.EncodeToString(sum[:])
}

// Register registers a new user with a hashed password.
// Returns ErrUsernameTaken if the username already exists (mapped from repository.ErrConflict).
// Note: Pre-check has been removed to close the registration timing oracle (~1ms for taken vs ~100ms for new becomes ~100ms for both).
func (s *Service) Register(ctx context.Context, username, password string) (repository.User, error) {
	hash, err := HashPassword(password)
	if err != nil {
		return repository.User{}, fmt.Errorf("hash password: %w", err)
	}

	user, err := s.userRepo.Create(ctx, username, hash)
	if errors.Is(err, repository.ErrConflict) {
		return repository.User{}, ErrUsernameTaken
	}
	if err != nil {
		return repository.User{}, fmt.Errorf("create user: %w", err)
	}

	if s.auditLogger != nil {
		targetID := user.ID.String()
		_ = s.auditLogger.Log(ctx, repository.AuditEvent{
			ActorID:  &user.ID,
			Action:   "auth.register",
			TargetID: &targetID,
			Metadata: map[string]any{"username": user.Username},
		})
	}
	return user, nil
}

// Login authenticates a user, verifies throttling, and creates a session.
// Wrong password and unknown username return ErrInvalidCredentials to prevent enumeration.
func (s *Service) Login(ctx context.Context, username, password, ip string) (string, error) {
	now := s.now()
	s.gcThrottles(now)

	tKey := throttleKey(username, ip)
	bucket := s.getOrCreateBucket(tKey)

	bucket.mu.Lock()
	// Lockout expiration check
	if !bucket.lockedUntil.IsZero() && !now.Before(bucket.lockedUntil) {
		// Reset lock and window on lockout expiration
		bucket.lockedUntil = time.Time{}
		bucket.windowStart = now
		bucket.failures = 0
	} else if now.Sub(bucket.windowStart) >= windowDuration {
		// Sliding window reset using >= to avoid re-lock hazard when windowDuration == lockoutDuration (Fix 1)
		bucket.windowStart = now
		bucket.failures = 0
	}

	// Reachable only if gcThrottles did not evict; gcThrottles preserves locked buckets. Do not relax that check without adjusting this branch.
	if now.Before(bucket.lockedUntil) {
		bucket.mu.Unlock()
		if s.auditLogger != nil {
			_ = s.auditLogger.Log(ctx, repository.AuditEvent{
				ActorID:  nil,
				Action:   "auth.login_failure",
				Metadata: map[string]any{"reason": "throttled", "username": username, "ip": ip},
			})
		}
		return "", ErrThrottled
	}

	// Parallel-throttle bypass mitigation:
	// Increment failure counter before expensive VerifyPassword.
	// If failures exceed maxFailedAttempts, lock out immediately without verifying.
	bucket.failures++
	if bucket.failures > maxFailedAttempts {
		bucket.lockedUntil = now.Add(lockoutDuration)
		bucket.mu.Unlock()
		if s.auditLogger != nil {
			_ = s.auditLogger.Log(ctx, repository.AuditEvent{
				ActorID:  nil,
				Action:   "auth.login_failure",
				Metadata: map[string]any{"reason": "throttled", "username": username, "ip": ip},
			})
		}
		return "", ErrThrottled
	}
	bucket.mu.Unlock()

	user, err := s.userRepo.GetByUsername(ctx, username)
	isUserNotFound := errors.Is(err, repository.ErrNotFound)
	if err != nil && !isUserNotFound {
		return "", fmt.Errorf("get user: %w", err)
	}

	var valid bool
	if isUserNotFound {
		_, _ = VerifyPassword(dummyHash, password)
		valid = false
	} else {
		valid, err = VerifyPassword(user.PasswordHash, password)
		if err != nil {
			valid = false
		}
	}

	if !valid {
		if s.auditLogger != nil {
			_ = s.auditLogger.Log(ctx, repository.AuditEvent{
				ActorID:  nil,
				Action:   "auth.login_failure",
				Metadata: map[string]any{"reason": "invalid_credentials", "username": username, "ip": ip},
			})
		}
		return "", ErrInvalidCredentials
	}

	// Successful login: reset failures to 0 and clear lockout
	bucket.mu.Lock()
	bucket.failures = 0
	bucket.windowStart = now
	bucket.lockedUntil = time.Time{}
	bucket.mu.Unlock()

	token, err := s.sessionStore.Create(ctx, user.ID)
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}

	if s.auditLogger != nil {
		targetID := user.ID.String()
		_ = s.auditLogger.Log(ctx, repository.AuditEvent{
			ActorID:  &user.ID,
			Action:   "auth.login_success",
			TargetID: &targetID,
			Metadata: map[string]any{"username": user.Username, "ip": ip},
		})
	}
	return token, nil
}

func (s *Service) Logout(ctx context.Context, token string) error {
	// Look up session first to retrieve userID for audit log before deletion
	var userID *uuid.UUID
	if sess, err := s.sessionStore.Lookup(ctx, token); err == nil && sess != nil {
		userID = &sess.UserID
	}

	err := s.sessionStore.Delete(ctx, token)
	if err == nil && s.auditLogger != nil {
		var targetID *string
		if userID != nil {
			sID := userID.String()
			targetID = &sID
		}
		_ = s.auditLogger.Log(ctx, repository.AuditEvent{
			ActorID:  userID,
			Action:   "auth.logout",
			TargetID: targetID,
		})
	}
	return err
}
