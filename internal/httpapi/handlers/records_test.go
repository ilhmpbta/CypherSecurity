package handlers

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
	"github.com/stretchr/testify/assert"
)

type fakeRecordService struct {
	listFn   func(ctx context.Context, ownerID uuid.UUID) ([]repository.PersonalRecord, error)
	createFn func(ctx context.Context, ownerID uuid.UUID, dataType string, payload map[string]any) (repository.PersonalRecord, error)
	updateFn func(ctx context.Context, id, ownerID uuid.UUID, dataType string, payload map[string]any) (repository.PersonalRecord, error)
	deleteFn func(ctx context.Context, id, ownerID uuid.UUID) error
}

func (f *fakeRecordService) List(ctx context.Context, ownerID uuid.UUID) ([]repository.PersonalRecord, error) {
	if f.listFn != nil {
		return f.listFn(ctx, ownerID)
	}
	return nil, nil
}
func (f *fakeRecordService) Create(ctx context.Context, ownerID uuid.UUID, dataType string, payload map[string]any) (repository.PersonalRecord, error) {
	if f.createFn != nil {
		return f.createFn(ctx, ownerID, dataType, payload)
	}
	return repository.PersonalRecord{}, nil
}
func (f *fakeRecordService) Update(ctx context.Context, id, ownerID uuid.UUID, dataType string, payload map[string]any) (repository.PersonalRecord, error) {
	if f.updateFn != nil {
		return f.updateFn(ctx, id, ownerID, dataType, payload)
	}
	return repository.PersonalRecord{}, nil
}
func (f *fakeRecordService) Delete(ctx context.Context, id, ownerID uuid.UUID) error {
	if f.deleteFn != nil {
		return f.deleteFn(ctx, id, ownerID)
	}
	return nil
}

func TestRecordsHandlerInstantiation(t *testing.T) {
	svc := &fakeRecordService{}
	h := NewRecordsHandler(svc)
	assert.NotNil(t, h)
}
