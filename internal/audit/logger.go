package audit

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
)

// Logger writes structured, redacted audit events and supports reading them by actor.
type Logger struct {
	repo repository.AuditRepo
}

func NewLogger(repo repository.AuditRepo) *Logger {
	return &Logger{repo: repo}
}

// Log writes a single audit event, applying redaction to metadata.
func (l *Logger) Log(ctx context.Context, e repository.AuditEvent) error {
	if e.Metadata != nil {
		e.Metadata = sanitizeMetadata(e.Metadata)
	}
	return l.repo.Insert(ctx, e)
}

// ListByActor satisfies handlers.AuditService.
func (l *Logger) ListByActor(ctx context.Context, actorID uuid.UUID, limit int) ([]repository.AuditEvent, error) {
	return l.repo.ListByActor(ctx, actorID, limit)
}

// sanitizeMetadata drops any key matching sensitive terms (case-insensitive substring)
// and caps map size at 16 keys.
func sanitizeMetadata(m map[string]any) map[string]any {
	out := make(map[string]any)
	count := 0
	for k, v := range m {
		if count >= 16 {
			break
		}
		lower := strings.ToLower(k)
		if strings.Contains(lower, "password") ||
			strings.Contains(lower, "token") ||
			strings.Contains(lower, "dek") ||
			strings.Contains(lower, "secret") ||
			strings.Contains(lower, "session") ||
			strings.Contains(lower, "wrapped_dek") ||
			strings.Contains(lower, "nonce") ||
			strings.Contains(lower, "plaintext") {
			continue
		}
		out[k] = v
		count++
	}
	return out
}
