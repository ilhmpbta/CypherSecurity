package sharing

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
)

var (
	ErrForbidden         = errors.New("forbidden")
	ErrNotFound          = errors.New("not_found")
	ErrInvalidTransition = errors.New("invalid_transition")
	ErrValidationFailed  = errors.New("validation_failed")
	ErrNoActiveShare     = errors.New("no_active_share")
	ErrConflict          = errors.New("conflict")
	ErrTooLarge          = errors.New("too_large")
	ErrInvalidContentType = errors.New("invalid_content_type")
)

type ShareStatus string

const (
	StatusPending  ShareStatus = "pending"
	StatusApproved ShareStatus = "approved"
	StatusRejected ShareStatus = "rejected"
	StatusRevoked  ShareStatus = "revoked"
)

type ShareIdentity struct {
	ID          uuid.UUID `json:"id"`
	Username    string    `json:"username"`
	Fingerprint string    `json:"fingerprint"`
}

type ShareRequest struct {
	ID          uuid.UUID     `json:"id"`
	FileID      uuid.UUID     `json:"file_id"`
	FileName    string        `json:"file_name"`
	Owner       ShareIdentity `json:"owner"`
	Requester   ShareIdentity `json:"requester"`
	Status      ShareStatus   `json:"status"`
	Note        *string       `json:"note"`
	RequestedAt time.Time     `json:"requested_at"`
	DecidedAt   *time.Time    `json:"decided_at"`
	DeliveredAt *time.Time    `json:"delivered_at"`
	ImportedAt  *time.Time    `json:"imported_at"`
	RevokedAt   *time.Time    `json:"revoked_at"`
}

type ActiveShare struct {
	Request    ShareRequest
	WrappedDEK []byte
}

type FileShareMeta struct {
	Access               string
	MyPendingRequestID   *uuid.UUID
	PendingRequestsCount int
	ShareState           string
}

func FromRecord(rec repository.ShareRecord) ShareRequest {
	return ShareRequest{
		ID:       rec.ID,
		FileID:   rec.FileID,
		FileName: rec.FileName,
		Owner: ShareIdentity{
			ID:          rec.OwnerID,
			Username:    rec.OwnerUsername,
			Fingerprint: rec.OwnerFingerprint,
		},
		Requester: ShareIdentity{
			ID:          rec.RequesterID,
			Username:    rec.RequesterUsername,
			Fingerprint: rec.RequesterFingerprint,
		},
		Status:      ShareStatus(rec.Status),
		Note:        rec.Note,
		RequestedAt: rec.RequestedAt,
		DecidedAt:   rec.DecidedAt,
		DeliveredAt: rec.DeliveredAt,
		ImportedAt:  rec.ImportedAt,
		RevokedAt:   rec.RevokedAt,
	}
}
