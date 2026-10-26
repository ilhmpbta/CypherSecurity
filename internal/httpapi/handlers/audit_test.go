package handlers

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
	"github.com/stretchr/testify/assert"
)

type fakeAuditService struct {
	listFn func(ctx context.Context, actorID uuid.UUID, limit int) ([]repository.AuditEvent, error)
}

func (f *fakeAuditService) ListByActor(ctx context.Context, actorID uuid.UUID, limit int) ([]repository.AuditEvent, error) {
	if f.listFn != nil {
		return f.listFn(ctx, actorID, limit)
	}
	return nil, nil
}

func TestAuditHandlerInstantiation(t *testing.T) {
	svc := &fakeAuditService{}
	h := NewAuditHandler(svc)
	assert.NotNil(t, h)
}
