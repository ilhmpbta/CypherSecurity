package audit

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
)

type fakeAuditRepo struct {
	events []repository.AuditEvent
}

func (f *fakeAuditRepo) Insert(ctx context.Context, e repository.AuditEvent) error {
	f.events = append(f.events, e)
	return nil
}

func (f *fakeAuditRepo) ListByActor(ctx context.Context, actorID uuid.UUID, limit int) ([]repository.AuditEvent, error) {
	var results []repository.AuditEvent
	for _, e := range f.events {
		if e.ActorID != nil && *e.ActorID == actorID {
			results = append(results, e)
			if limit > 0 && len(results) >= limit {
				break
			}
		}
	}
	return results, nil
}

func (f *fakeAuditRepo) ListAll(ctx context.Context, limit int) ([]repository.AuditEvent, error) {
	return f.events, nil
}

func TestAuditLogger_Sanitization(t *testing.T) {
	repo := &fakeAuditRepo{}
	logger := NewLogger(repo)
	ctx := context.Background()
	actorID := uuid.New()

	meta := map[string]any{
		"username":        "alice",
		"password":        "SuperSecret123!",
		"session_token":   "abc123xyz",
		"wrapped_dek":     []byte{1, 2, 3},
		"action_status":   "success",
		"plaintext_bytes": 1024,
	}

	err := logger.Log(ctx, repository.AuditEvent{
		ActorID:  &actorID,
		Action:   "auth.login_success",
		Metadata: meta,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(repo.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(repo.events))
	}

	savedMeta := repo.events[0].Metadata

	// Check that sensitive keys were stripped
	for _, badKey := range []string{"password", "session_token", "wrapped_dek", "plaintext_bytes"} {
		if _, exists := savedMeta[badKey]; exists {
			t.Errorf("sensitive key %q was not stripped from metadata", badKey)
		}
	}

	// Check that non-sensitive keys remain
	if savedMeta["username"] != "alice" {
		t.Errorf("expected username 'alice', got %v", savedMeta["username"])
	}
	if savedMeta["action_status"] != "success" {
		t.Errorf("expected action_status 'success', got %v", savedMeta["action_status"])
	}
}
