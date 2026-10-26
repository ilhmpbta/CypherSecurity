package records

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
)

type fakeRecordRepo struct {
	records map[uuid.UUID]repository.PersonalRecord
}

func newFakeRecordRepo() *fakeRecordRepo {
	return &fakeRecordRepo{records: make(map[uuid.UUID]repository.PersonalRecord)}
}

func (f *fakeRecordRepo) Create(ctx context.Context, r repository.PersonalRecord) (repository.PersonalRecord, error) {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	r.CreatedAt = time.Now()
	r.UpdatedAt = r.CreatedAt
	f.records[r.ID] = r
	return r, nil
}

func (f *fakeRecordRepo) GetByIDForOwner(ctx context.Context, id, ownerID uuid.UUID) (repository.PersonalRecord, error) {
	r, ok := f.records[id]
	if !ok || r.OwnerID != ownerID {
		return repository.PersonalRecord{}, repository.ErrNotFound
	}
	return r, nil
}

func (f *fakeRecordRepo) ListByOwner(ctx context.Context, ownerID uuid.UUID) ([]repository.PersonalRecord, error) {
	var list []repository.PersonalRecord
	for _, r := range f.records {
		if r.OwnerID == ownerID {
			list = append(list, r)
		}
	}
	return list, nil
}

func (f *fakeRecordRepo) UpdateForOwner(ctx context.Context, r repository.PersonalRecord, ownerID uuid.UUID) (repository.PersonalRecord, error) {
	existing, ok := f.records[r.ID]
	if !ok || existing.OwnerID != ownerID {
		return repository.PersonalRecord{}, repository.ErrNotFound
	}
	r.OwnerID = ownerID
	r.CreatedAt = existing.CreatedAt
	r.UpdatedAt = time.Now()
	f.records[r.ID] = r
	return r, nil
}

func (f *fakeRecordRepo) DeleteByOwner(ctx context.Context, id, ownerID uuid.UUID) error {
	existing, ok := f.records[id]
	if !ok || existing.OwnerID != ownerID {
		return repository.ErrNotFound
	}
	delete(f.records, id)
	return nil
}

func TestRecordsService(t *testing.T) {
	repo := newFakeRecordRepo()
	svc := NewService(repo)
	ctx := context.Background()
	ownerID := uuid.New()
	otherOwnerID := uuid.New()

	// 1. List empty
	list, err := svc.List(ctx, ownerID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected 0 records, got %d", len(list))
	}

	// 2. Create
	created, err := svc.Create(ctx, ownerID, "password", map[string]any{"site": "example.com"})
	if err != nil {
		t.Fatalf("create error: %v", err)
	}
	if created.DataType != "password" {
		t.Errorf("expected datatype password, got %s", created.DataType)
	}

	// 3. List multiple / check owner separation
	_, _ = svc.Create(ctx, otherOwnerID, "note", map[string]any{"secret": "stuff"})
	list, err = svc.List(ctx, ownerID)
	if err != nil {
		t.Fatalf("list error: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("expected 1 record for ownerID, got %d", len(list))
	}

	// 4. Update success
	updated, err := svc.Update(ctx, created.ID, ownerID, "login", map[string]any{"site": "updated.com"})
	if err != nil {
		t.Fatalf("update error: %v", err)
	}
	if updated.DataType != "login" {
		t.Errorf("expected datatype login, got %s", updated.DataType)
	}

	// 5. Update cross-user (should return not found)
	_, err = svc.Update(ctx, created.ID, otherOwnerID, "hacked", nil)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("expected ErrNotFound for cross-user update, got %v", err)
	}

	// 6. Delete success
	err = svc.Delete(ctx, created.ID, ownerID)
	if err != nil {
		t.Fatalf("delete error: %v", err)
	}

	// 7. Delete not found
	err = svc.Delete(ctx, created.ID, ownerID)
	if err != repository.ErrNotFound {
		t.Errorf("expected ErrNotFound on second delete, got %v", err)
	}
}
