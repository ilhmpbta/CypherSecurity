package records

import (
	"context"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
)

// Service handles CRUD for structured personal data.
type Service struct {
	repo repository.PersonalRecordRepo
}

func NewService(repo repository.PersonalRecordRepo) *Service {
	return &Service{repo: repo}
}

func (s *Service) List(ctx context.Context, ownerID uuid.UUID) ([]repository.PersonalRecord, error) {
	return s.repo.ListByOwner(ctx, ownerID)
}

func (s *Service) Create(ctx context.Context, ownerID uuid.UUID, dataType string, payload map[string]any) (repository.PersonalRecord, error) {
	if payload == nil {
		payload = make(map[string]any)
	}
	record := repository.PersonalRecord{
		ID:       uuid.New(),
		OwnerID:  ownerID,
		DataType: dataType,
		Payload:  payload,
	}
	return s.repo.Create(ctx, record)
}

func (s *Service) Update(ctx context.Context, id, ownerID uuid.UUID, dataType string, payload map[string]any) (repository.PersonalRecord, error) {
	if payload == nil {
		payload = make(map[string]any)
	}
	existing, err := s.repo.GetByIDForOwner(ctx, id, ownerID)
	if err != nil {
		return repository.PersonalRecord{}, err
	}
	existing.DataType = dataType
	existing.Payload = payload
	return s.repo.UpdateForOwner(ctx, existing, ownerID)
}

func (s *Service) Delete(ctx context.Context, id, ownerID uuid.UUID) error {
	return s.repo.DeleteByOwner(ctx, id, ownerID)
}
