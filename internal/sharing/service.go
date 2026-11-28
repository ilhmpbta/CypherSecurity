package sharing

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/crypto/production"
	"github.com/ilhmpbta/CypherSecurity/internal/keys"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
)

type AuditLogger interface {
	Log(ctx context.Context, e repository.AuditEvent) error
}

type Service struct {
	repo        repository.ShareRepo
	fileRepo    repository.FileRepo
	km          *production.KeyManager
	keysSvc     keys.Service
	auditLogger AuditLogger
	now         func() time.Time
}

func NewService(
	repo repository.ShareRepo,
	fileRepo repository.FileRepo,
	km *production.KeyManager,
	keysSvc keys.Service,
	auditLogger AuditLogger,
) *Service {
	return &Service{
		repo:        repo,
		fileRepo:    fileRepo,
		km:          km,
		keysSvc:     keysSvc,
		auditLogger: auditLogger,
		now:         time.Now,
	}
}

func (s *Service) SetNow(nowFunc func() time.Time) {
	s.now = nowFunc
}

func (s *Service) ensureIdentities(ctx context.Context, rec *repository.ShareRecord) {
	if s.keysSvc != nil {
		if rec.OwnerFingerprint == "" {
			if kp, err := s.keysSvc.Get(ctx, rec.OwnerID); err == nil {
				rec.OwnerFingerprint = kp.Fingerprint
			}
		}
		if rec.RequesterFingerprint == "" {
			if kp, err := s.keysSvc.Get(ctx, rec.RequesterID); err == nil {
				rec.RequesterFingerprint = kp.Fingerprint
			}
		}
	}
}

func (s *Service) Request(ctx context.Context, requesterID, fileID uuid.UUID, note string) (ShareRequest, bool, error) {
	file, err := s.fileRepo.GetByID(ctx, fileID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ShareRequest{}, false, ErrNotFound
		}
		return ShareRequest{}, false, err
	}

	if file.OwnerID == requesterID {
		return ShareRequest{}, false, ErrForbidden
	}

	existing, err := s.repo.GetPendingRequest(ctx, fileID, requesterID)
	if err == nil {
		s.ensureIdentities(ctx, &existing)
		return FromRecord(existing), false, nil
	}
	if !errors.Is(err, repository.ErrNotFound) {
		return ShareRequest{}, false, err
	}

	var notePtr *string
	if note != "" {
		notePtr = &note
	}

	rec := repository.ShareRecord{
		ID:          uuid.New(),
		FileID:      fileID,
		FileName:    file.OriginalName,
		OwnerID:     file.OwnerID,
		RequesterID: requesterID,
		Status:      string(StatusPending),
		Note:        notePtr,
		RequestedAt: s.now(),
	}

	s.ensureIdentities(ctx, &rec)

	created, err := s.repo.CreateRequest(ctx, rec)
	if err != nil {
		return ShareRequest{}, false, err
	}

	s.ensureIdentities(ctx, &created)

	if s.auditLogger != nil {
		targetID := created.ID.String()
		_ = s.auditLogger.Log(ctx, repository.AuditEvent{
			ActorID:  &requesterID,
			Action:   "shares.request",
			TargetID: &targetID,
			Metadata: map[string]any{
				"file_id":  fileID.String(),
				"owner_id": file.OwnerID.String(),
			},
		})
	}

	return FromRecord(created), true, nil
}

func (s *Service) Reject(ctx context.Context, shareID uuid.UUID, ownerID uuid.UUID) (ShareRequest, error) {
	record, err := s.repo.GetRequestByID(ctx, shareID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ShareRequest{}, ErrNotFound
		}
		return ShareRequest{}, err
	}

	if record.OwnerID != ownerID {
		return ShareRequest{}, ErrForbidden
	}

	if record.Status != string(StatusPending) {
		return ShareRequest{}, ErrInvalidTransition
	}

	now := s.now()
	record.Status = string(StatusRejected)
	record.DecidedAt = &now

	if err := s.repo.UpdateRequest(ctx, record); err != nil {
		return ShareRequest{}, err
	}

	s.ensureIdentities(ctx, &record)

	if s.auditLogger != nil {
		targetID := shareID.String()
		_ = s.auditLogger.Log(ctx, repository.AuditEvent{
			ActorID:  &ownerID,
			Action:   "shares.reject",
			TargetID: &targetID,
			Metadata: map[string]any{
				"file_id":      record.FileID.String(),
				"requester_id": record.RequesterID.String(),
			},
		})
	}

	return FromRecord(record), nil
}

func (s *Service) Revoke(ctx context.Context, shareID uuid.UUID, ownerID uuid.UUID) (ShareRequest, error) {
	record, err := s.repo.GetRequestByID(ctx, shareID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ShareRequest{}, ErrNotFound
		}
		return ShareRequest{}, err
	}

	if record.OwnerID != ownerID {
		return ShareRequest{}, ErrForbidden
	}

	if record.Status != string(StatusApproved) || record.RevokedAt != nil {
		return ShareRequest{}, ErrInvalidTransition
	}

	now := s.now()
	record.Status = string(StatusRevoked)
	record.RevokedAt = &now
	if record.DecidedAt == nil {
		record.DecidedAt = &now
	}

	if err := s.repo.UpdateRequest(ctx, record); err != nil {
		return ShareRequest{}, err
	}

	s.ensureIdentities(ctx, &record)

	if s.auditLogger != nil {
		targetID := shareID.String()
		_ = s.auditLogger.Log(ctx, repository.AuditEvent{
			ActorID:  &ownerID,
			Action:   "shares.revoke",
			TargetID: &targetID,
			Metadata: map[string]any{
				"file_id":      record.FileID.String(),
				"requester_id": record.RequesterID.String(),
			},
		})
	}

	return FromRecord(record), nil
}

func (s *Service) Export(ctx context.Context, shareID uuid.UUID, ownerSess keys.Session) ([]byte, string, error) {
	if len(ownerSess.WrapKey) == 0 {
		return nil, "", keys.ErrSessionLocked
	}

	record, err := s.repo.GetRequestByID(ctx, shareID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, "", ErrNotFound
		}
		return nil, "", err
	}

	if record.OwnerID != ownerSess.UserID {
		return nil, "", ErrForbidden
	}

	if record.Status != string(StatusApproved) || record.RevokedAt != nil {
		return nil, "", ErrInvalidTransition
	}

	key, err := s.repo.GetKeyByRequestID(ctx, shareID)
	if err != nil {
		return nil, "", fmt.Errorf("get share key: %w", err)
	}

	s.ensureIdentities(ctx, &record)

	req := FromRecord(record)
	blob, err := EncodeBlob(req, key.WrappedDEK, func(digest []byte) ([]byte, error) {
		return s.keysSvc.Sign(ctx, ownerSess, digest)
	})
	if err != nil {
		return nil, "", fmt.Errorf("encode blob: %w", err)
	}

	now := s.now()
	record.DeliveredAt = &now
	_ = s.repo.UpdateRequest(ctx, record)

	if s.auditLogger != nil {
		targetID := shareID.String()
		_ = s.auditLogger.Log(ctx, repository.AuditEvent{
			ActorID:  &ownerSess.UserID,
			Action:   "shares.export",
			TargetID: &targetID,
			Metadata: map[string]any{
				"file_id":      record.FileID.String(),
				"requester_id": record.RequesterID.String(),
			},
		})
	}

	filename := record.FileName
	if filename == "" {
		filename = "share"
	}

	return blob, filename, nil
}

func (s *Service) Import(ctx context.Context, requesterID uuid.UUID, blob []byte) (ShareRequest, error) {
	if len(blob) > MaxBlobSize {
		return ShareRequest{}, ErrTooLarge
	}

	decoded, err := DecodeBlob(blob)
	if err != nil {
		return ShareRequest{}, ErrValidationFailed
	}

	record, err := s.repo.GetRequestByID(ctx, decoded.Header.ShareRequestID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ShareRequest{}, ErrNotFound
		}
		return ShareRequest{}, err
	}

	if record.RequesterID != requesterID {
		return ShareRequest{}, ErrForbidden
	}

	if record.Status != string(StatusApproved) || record.RevokedAt != nil {
		return ShareRequest{}, ErrInvalidTransition
	}

	s.ensureIdentities(ctx, &record)

	req := FromRecord(record)
	err = VerifyBlob(decoded, req, func(ownerID uuid.UUID, digest, sig []byte) (bool, error) {
		return s.keysSvc.Verify(ctx, ownerID, digest, sig)
	})
	if err != nil {
		return ShareRequest{}, ErrValidationFailed
	}

	// Idempotent re-import
	if record.ImportedAt != nil {
		return FromRecord(record), nil
	}

	now := s.now()
	record.ImportedAt = &now
	if err := s.repo.UpdateRequest(ctx, record); err != nil {
		return ShareRequest{}, err
	}

	if s.auditLogger != nil {
		targetID := record.ID.String()
		_ = s.auditLogger.Log(ctx, repository.AuditEvent{
			ActorID:  &requesterID,
			Action:   "shares.import",
			TargetID: &targetID,
			Metadata: map[string]any{
				"file_id":  record.FileID.String(),
				"owner_id": record.OwnerID.String(),
			},
		})
	}

	return FromRecord(record), nil
}

func (s *Service) GetActiveShare(ctx context.Context, requesterID, fileID uuid.UUID) (*ActiveShare, error) {
	rec, key, err := s.repo.GetActiveShare(ctx, requesterID, fileID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrNoActiveShare
		}
		return nil, err
	}

	s.ensureIdentities(ctx, &rec)

	return &ActiveShare{
		Request:    FromRecord(rec),
		WrappedDEK: key.WrappedDEK,
	}, nil
}

func (s *Service) ListInbox(ctx context.Context, ownerID uuid.UUID, status string) ([]ShareRequest, error) {
	records, err := s.repo.ListInbox(ctx, ownerID, status)
	if err != nil {
		return nil, err
	}
	out := make([]ShareRequest, len(records))
	for i, r := range records {
		s.ensureIdentities(ctx, &r)
		out[i] = FromRecord(r)
	}
	return out, nil
}

func (s *Service) ListOutgoing(ctx context.Context, requesterID uuid.UUID, status string) ([]ShareRequest, error) {
	records, err := s.repo.ListOutgoing(ctx, requesterID, status)
	if err != nil {
		return nil, err
	}
	out := make([]ShareRequest, len(records))
	for i, r := range records {
		s.ensureIdentities(ctx, &r)
		out[i] = FromRecord(r)
	}
	return out, nil
}

func (s *Service) GetSharingMeta(ctx context.Context, userID uuid.UUID, files []repository.File) (map[uuid.UUID]FileShareMeta, error) {
	pendingCounts, err := s.repo.GetPendingCountsByOwner(ctx, userID)
	if err != nil {
		return nil, err
	}

	requesterShares, err := s.repo.GetRequesterShares(ctx, userID)
	if err != nil {
		return nil, err
	}

	sharesByFile := make(map[uuid.UUID][]repository.ShareRecord)
	for _, sr := range requesterShares {
		sharesByFile[sr.FileID] = append(sharesByFile[sr.FileID], sr)
	}

	metaMap := make(map[uuid.UUID]FileShareMeta, len(files))
	for _, f := range files {
		if f.OwnerID == userID {
			metaMap[f.ID] = FileShareMeta{
				Access:               "owner",
				MyPendingRequestID:   nil,
				PendingRequestsCount: pendingCounts[f.ID],
				ShareState:           "none",
			}
		} else {
			fileShares := sharesByFile[f.ID]
			var (
				myPendingID *uuid.UUID
				shareState  = "none"
			)

			// Find pending
			for _, sr := range fileShares {
				if sr.Status == string(StatusPending) {
					id := sr.ID
					myPendingID = &id
					break
				}
			}

			// Find non-rejected share state
			for _, sr := range fileShares {
				if sr.Status != string(StatusRejected) {
					if sr.RevokedAt != nil || sr.Status == string(StatusRevoked) {
						shareState = "revoked"
					} else if sr.ImportedAt != nil {
						shareState = "imported"
					} else if sr.Status == string(StatusApproved) {
						shareState = "approved"
					} else if sr.Status == string(StatusPending) {
						shareState = "pending"
					}
					break
				}
			}

			metaMap[f.ID] = FileShareMeta{
				Access:               "shared",
				MyPendingRequestID:   myPendingID,
				PendingRequestsCount: 0,
				ShareState:           shareState,
			}
		}
	}

	return metaMap, nil
}
