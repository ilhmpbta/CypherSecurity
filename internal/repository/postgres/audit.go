package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AuditRepo struct {
	pool *pgxpool.Pool
}

func NewAuditRepo(pool *pgxpool.Pool) *AuditRepo { return &AuditRepo{pool: pool} }

func (r *AuditRepo) Insert(ctx context.Context, e repository.AuditEvent) error {
	var actorID pgtype.UUID
	if e.ActorID != nil {
		actorID = toPgUUID(*e.ActorID)
	}
	var targetID *string
	if e.TargetID != nil {
		targetID = e.TargetID
	}
	_, err := r.pool.Exec(ctx,
		`INSERT INTO audit_events (actor_id, action, target_id, metadata)
		 VALUES ($1, $2, $3, $4)`,
		actorID, e.Action, targetID, e.Metadata,
	)
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

func (r *AuditRepo) ListByActor(ctx context.Context, actorID uuid.UUID, limit int) ([]repository.AuditEvent, error) {
	return r.list(ctx,
		`SELECT id, actor_id, action, target_id, metadata, created_at
		 FROM audit_events WHERE actor_id = $1
		 ORDER BY created_at DESC LIMIT $2`,
		toPgUUID(actorID), limit)
}

func (r *AuditRepo) ListAll(ctx context.Context, limit int) ([]repository.AuditEvent, error) {
	return r.list(ctx,
		`SELECT id, actor_id, action, target_id, metadata, created_at
		 FROM audit_events ORDER BY created_at DESC LIMIT $1`, limit)
}

func (r *AuditRepo) list(ctx context.Context, sql string, args ...any) ([]repository.AuditEvent, error) {
	rows, err := r.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()

	var out []repository.AuditEvent
	for rows.Next() {
		var (
			e        repository.AuditEvent
			actorID  pgtype.UUID
			targetID pgtype.Text
		)
		if err := rows.Scan(&e.ID, &actorID, &e.Action, &targetID, &e.Metadata, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		if actorID.Valid {
			u := fromPgUUID(actorID)
			e.ActorID = &u
		}
		if targetID.Valid {
			s := targetID.String
			e.TargetID = &s
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
