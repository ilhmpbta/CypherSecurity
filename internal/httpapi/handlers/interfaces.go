package handlers

import (
	"context"
	"io"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/files"
	"github.com/ilhmpbta/CypherSecurity/internal/keys"
	"github.com/ilhmpbta/CypherSecurity/internal/pdfsign"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
	"github.com/ilhmpbta/CypherSecurity/internal/sharing"
)

type AuthService interface {
	Register(ctx context.Context, username, password string) (repository.User, error)
	Login(ctx context.Context, username, password, ip string) (string, error)
	Logout(ctx context.Context, token string) error
}

type FileService interface {
	Upload(ctx context.Context, ownerID uuid.UUID, reader io.Reader, contentType, originalName string) (repository.File, error)
	List(ctx context.Context, ownerID uuid.UUID) ([]files.ListedFile, error)
	Download(ctx context.Context, id, ownerID uuid.UUID) (io.ReadCloser, repository.File, error)
	OpenShared(ctx context.Context, id uuid.UUID, keysSess keys.Session) (io.ReadCloser, repository.File, error)
	Delete(ctx context.Context, id, ownerID uuid.UUID) error
	Sign(ctx context.Context, id uuid.UUID, keysSess keys.Session) ([]pdfsign.SignatureVerificationResult, repository.File, error)
	Verify(ctx context.Context, id, userID uuid.UUID) ([]pdfsign.SignatureVerificationResult, repository.File, error)
}

type RecordService interface {
	List(ctx context.Context, ownerID uuid.UUID) ([]repository.PersonalRecord, error)
	Create(ctx context.Context, ownerID uuid.UUID, dataType string, payload map[string]any) (repository.PersonalRecord, error)
	Update(ctx context.Context, id, ownerID uuid.UUID, dataType string, payload map[string]any) (repository.PersonalRecord, error)
	Delete(ctx context.Context, id, ownerID uuid.UUID) error
}

type AuditService interface {
	ListByActor(ctx context.Context, actorID uuid.UUID, limit int) ([]repository.AuditEvent, error)
}

type SharingService interface {
	Request(ctx context.Context, requesterID, fileID uuid.UUID, note string) (sharing.ShareRequest, bool, error)
	Approve(ctx context.Context, shareID uuid.UUID, ownerSess keys.Session) (sharing.ShareRequest, error)
	Reject(ctx context.Context, shareID uuid.UUID, ownerID uuid.UUID) (sharing.ShareRequest, error)
	Revoke(ctx context.Context, shareID uuid.UUID, ownerID uuid.UUID) (sharing.ShareRequest, error)
	Export(ctx context.Context, shareID uuid.UUID, ownerSess keys.Session) ([]byte, string, error)
	Import(ctx context.Context, requesterID uuid.UUID, blob []byte) (sharing.ShareRequest, error)
	ListInbox(ctx context.Context, ownerID uuid.UUID, status string) ([]sharing.ShareRequest, error)
	ListOutgoing(ctx context.Context, requesterID uuid.UUID, status string) ([]sharing.ShareRequest, error)
}
