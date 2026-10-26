package handlers

import (
	"context"
	"io"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
)

type AuthService interface {
	Register(ctx context.Context, username, password string) (repository.User, error)
	Login(ctx context.Context, username, password, ip string) (string, error)
	Logout(ctx context.Context, token string) error
}

type FileService interface {
	Upload(ctx context.Context, ownerID uuid.UUID, reader io.Reader, contentType, originalName string) (repository.File, error)
	List(ctx context.Context, ownerID uuid.UUID) ([]repository.File, error)
	Download(ctx context.Context, id, ownerID uuid.UUID) (io.ReadCloser, repository.File, error)
	Delete(ctx context.Context, id, ownerID uuid.UUID) error
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
