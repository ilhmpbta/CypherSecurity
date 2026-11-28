package sharing

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/keys"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
)

func (s *Service) Approve(ctx context.Context, shareID uuid.UUID, ownerSess keys.Session) (ShareRequest, error) {
	if len(ownerSess.WrapKey) == 0 {
		return ShareRequest{}, keys.ErrSessionLocked
	}

	record, err := s.repo.GetRequestByID(ctx, shareID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ShareRequest{}, ErrNotFound
		}
		return ShareRequest{}, err
	}

	if record.OwnerID != ownerSess.UserID {
		return ShareRequest{}, ErrForbidden
	}

	if record.Status != string(StatusPending) {
		return ShareRequest{}, ErrInvalidTransition
	}

	file, err := s.fileRepo.GetByIDForOwner(ctx, record.FileID, ownerSess.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ShareRequest{}, ErrNotFound
		}
		return ShareRequest{}, err
	}

	dek, err := s.km.Unwrap(file.WrappedDEK, 1)
	if err != nil {
		return ShareRequest{}, fmt.Errorf("unwrap file dek: %w", err)
	}

	wrappedDEK, err := s.keysSvc.WrapForRequester(ctx, record.RequesterID, dek)
	if err != nil {
		return ShareRequest{}, fmt.Errorf("wrap dek for requester: %w", err)
	}

	decidedAt := s.now()
	updatedRecord, err := s.repo.ApproveShare(ctx, shareID, decidedAt, wrappedDEK)
	if err != nil {
		if errors.Is(err, repository.ErrConflict) {
			return ShareRequest{}, ErrInvalidTransition
		}
		return ShareRequest{}, err
	}

	if s.auditLogger != nil {
		targetID := shareID.String()
		_ = s.auditLogger.Log(ctx, repository.AuditEvent{
			ActorID:  &ownerSess.UserID,
			Action:   "shares.approve",
			TargetID: &targetID,
			Metadata: map[string]any{
				"file_id":      record.FileID.String(),
				"requester_id": record.RequesterID.String(),
			},
		})
	}

	return FromRecord(updatedRecord), nil
}
