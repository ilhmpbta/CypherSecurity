package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

var ErrNotFound = errors.New("not found")

type User struct {
	ID           uuid.UUID
	Username     string
	PasswordHash string
	CreatedAt    time.Time
}

type File struct {
	ID             uuid.UUID
	OwnerID        uuid.UUID
	StorageKey     string
	OriginalName   string
	ContentType    string
	PlaintextSize  int64
	CiphertextSize int64
	AlgID          string
	WrappedDEK     []byte
	NoncePrefix    []byte
	CreatedAt      time.Time
}

type PersonalRecord struct {
	ID        uuid.UUID
	OwnerID   uuid.UUID
	DataType  string
	Payload   map[string]any
	CreatedAt time.Time
	UpdatedAt time.Time
}

type AuditEvent struct {
	ID        int64
	ActorID   *uuid.UUID
	Action    string
	TargetID  *string
	Metadata  map[string]any
	CreatedAt time.Time
}

type Session struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	ExpiresAt time.Time
	CreatedAt time.Time
}

type UserRepo interface {
	Create(ctx context.Context, username, passwordHash string) (User, error)
	GetByUsername(ctx context.Context, username string) (User, error)
	GetByID(ctx context.Context, id uuid.UUID) (User, error)
}

// Every method that touches a stored_files row takes ownerID.
type FileRepo interface {
	Create(ctx context.Context, f File) (File, error)
	GetByIDForOwner(ctx context.Context, id, ownerID uuid.UUID) (File, error)
	ListByOwner(ctx context.Context, ownerID uuid.UUID) ([]File, error)
	DeleteByOwner(ctx context.Context, id, ownerID uuid.UUID) error
}

type PersonalRecordRepo interface {
	Create(ctx context.Context, r PersonalRecord) (PersonalRecord, error)
	GetByIDForOwner(ctx context.Context, id, ownerID uuid.UUID) (PersonalRecord, error)
	ListByOwner(ctx context.Context, ownerID uuid.UUID) ([]PersonalRecord, error)
	UpdateForOwner(ctx context.Context, r PersonalRecord, ownerID uuid.UUID) (PersonalRecord, error)
	DeleteByOwner(ctx context.Context, id, ownerID uuid.UUID) error
}

type AuditRepo interface {
	Insert(ctx context.Context, e AuditEvent) error
	ListByActor(ctx context.Context, actorID uuid.UUID, limit int) ([]AuditEvent, error)
	ListAll(ctx context.Context, limit int) ([]AuditEvent, error)
}

type SessionRepo interface {
	Create(ctx context.Context, s Session) error
	GetByID(ctx context.Context, id uuid.UUID) (Session, error)
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteExpired(ctx context.Context, before time.Time) (int64, error)
}
