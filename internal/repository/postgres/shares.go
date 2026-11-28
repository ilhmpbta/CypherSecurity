package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ShareRepo struct {
	pool *pgxpool.Pool
}

func NewShareRepo(pool *pgxpool.Pool) *ShareRepo {
	return &ShareRepo{pool: pool}
}

const selectShareRecordFields = `
	sr.id, sr.file_id, f.original_name,
	sr.owner_id, u_owner.username, COALESCE(kp_owner.fingerprint, ''),
	sr.requester_id, u_req.username, COALESCE(kp_req.fingerprint, ''),
	sr.status, sr.note,
	sr.requested_at, sr.decided_at, sr.delivered_at, sr.imported_at, sr.revoked_at
FROM share_requests sr
JOIN stored_files f ON f.id = sr.file_id
JOIN users u_owner ON u_owner.id = sr.owner_id
LEFT JOIN user_keypairs kp_owner ON kp_owner.user_id = sr.owner_id
JOIN users u_req ON u_req.id = sr.requester_id
LEFT JOIN user_keypairs kp_req ON kp_req.user_id = sr.requester_id
`

func scanShareRecord(row pgx.Row) (repository.ShareRecord, error) {
	var (
		rec                    repository.ShareRecord
		id, fileID, ownerID, reqID pgtype.UUID
		decidedAt, deliveredAt, importedAt, revokedAt pgtype.Timestamptz
	)

	err := row.Scan(
		&id, &fileID, &rec.FileName,
		&ownerID, &rec.OwnerUsername, &rec.OwnerFingerprint,
		&reqID, &rec.RequesterUsername, &rec.RequesterFingerprint,
		&rec.Status, &rec.Note,
		&rec.RequestedAt, &decidedAt, &deliveredAt, &importedAt, &revokedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ShareRecord{}, repository.ErrNotFound
		}
		return repository.ShareRecord{}, err
	}

	rec.ID = fromPgUUID(id)
	rec.FileID = fromPgUUID(fileID)
	rec.OwnerID = fromPgUUID(ownerID)
	rec.RequesterID = fromPgUUID(reqID)
	if decidedAt.Valid {
		t := decidedAt.Time
		rec.DecidedAt = &t
	}
	if deliveredAt.Valid {
		t := deliveredAt.Time
		rec.DeliveredAt = &t
	}
	if importedAt.Valid {
		t := importedAt.Time
		rec.ImportedAt = &t
	}
	if revokedAt.Valid {
		t := revokedAt.Time
		rec.RevokedAt = &t
	}

	return rec, nil
}

func (r *ShareRepo) CreateRequest(ctx context.Context, req repository.ShareRecord) (repository.ShareRecord, error) {
	var id pgtype.UUID
	err := r.pool.QueryRow(ctx,
		`INSERT INTO share_requests (file_id, owner_id, requester_id, status, note, requested_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id`,
		toPgUUID(req.FileID), toPgUUID(req.OwnerID), toPgUUID(req.RequesterID),
		req.Status, req.Note, req.RequestedAt,
	).Scan(&id)
	if err != nil {
		return repository.ShareRecord{}, fmt.Errorf("create share request: %w", err)
	}

	return r.GetRequestByID(ctx, fromPgUUID(id))
}

func (r *ShareRepo) GetRequestByID(ctx context.Context, id uuid.UUID) (repository.ShareRecord, error) {
	query := "SELECT " + selectShareRecordFields + " WHERE sr.id = $1"
	row := r.pool.QueryRow(ctx, query, toPgUUID(id))
	rec, err := scanShareRecord(row)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return repository.ShareRecord{}, repository.ErrNotFound
		}
		return repository.ShareRecord{}, fmt.Errorf("get share request by id: %w", err)
	}
	return rec, nil
}

func (r *ShareRepo) GetPendingRequest(ctx context.Context, fileID, requesterID uuid.UUID) (repository.ShareRecord, error) {
	query := "SELECT " + selectShareRecordFields + " WHERE sr.file_id = $1 AND sr.requester_id = $2 AND sr.status = 'pending'"
	row := r.pool.QueryRow(ctx, query, toPgUUID(fileID), toPgUUID(requesterID))
	rec, err := scanShareRecord(row)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return repository.ShareRecord{}, repository.ErrNotFound
		}
		return repository.ShareRecord{}, fmt.Errorf("get pending request: %w", err)
	}
	return rec, nil
}

func (r *ShareRepo) ListInbox(ctx context.Context, ownerID uuid.UUID, status string) ([]repository.ShareRecord, error) {
	var (
		rows pgx.Rows
		err  error
	)
	if status != "" {
		query := "SELECT " + selectShareRecordFields + " WHERE sr.owner_id = $1 AND sr.status = $2 ORDER BY sr.requested_at DESC"
		rows, err = r.pool.Query(ctx, query, toPgUUID(ownerID), status)
	} else {
		query := "SELECT " + selectShareRecordFields + " WHERE sr.owner_id = $1 ORDER BY sr.requested_at DESC"
		rows, err = r.pool.Query(ctx, query, toPgUUID(ownerID))
	}
	if err != nil {
		return nil, fmt.Errorf("list inbox: %w", err)
	}
	defer rows.Close()

	var list []repository.ShareRecord
	for rows.Next() {
		rec, err := scanShareRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("scan inbox record: %w", err)
		}
		list = append(list, rec)
	}
	return list, rows.Err()
}

func (r *ShareRepo) ListOutgoing(ctx context.Context, requesterID uuid.UUID, status string) ([]repository.ShareRecord, error) {
	var (
		rows pgx.Rows
		err  error
	)
	if status != "" {
		query := "SELECT " + selectShareRecordFields + " WHERE sr.requester_id = $1 AND sr.status = $2 ORDER BY sr.requested_at DESC"
		rows, err = r.pool.Query(ctx, query, toPgUUID(requesterID), status)
	} else {
		query := "SELECT " + selectShareRecordFields + " WHERE sr.requester_id = $1 ORDER BY sr.requested_at DESC"
		rows, err = r.pool.Query(ctx, query, toPgUUID(requesterID))
	}
	if err != nil {
		return nil, fmt.Errorf("list outgoing: %w", err)
	}
	defer rows.Close()

	var list []repository.ShareRecord
	for rows.Next() {
		rec, err := scanShareRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("scan outgoing record: %w", err)
		}
		list = append(list, rec)
	}
	return list, rows.Err()
}

func (r *ShareRepo) UpdateRequest(ctx context.Context, req repository.ShareRecord) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE share_requests
		 SET status = $1, note = $2, decided_at = $3, delivered_at = $4, imported_at = $5, revoked_at = $6
		 WHERE id = $7`,
		req.Status, req.Note, req.DecidedAt, req.DeliveredAt, req.ImportedAt, req.RevokedAt,
		toPgUUID(req.ID),
	)
	if err != nil {
		return fmt.Errorf("update share request: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *ShareRepo) ApproveShare(ctx context.Context, requestID uuid.UUID, decidedAt time.Time, wrappedDEK []byte) (repository.ShareRecord, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return repository.ShareRecord{}, fmt.Errorf("begin tx for approve: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var fileID pgtype.UUID
	err = tx.QueryRow(ctx,
		`UPDATE share_requests
		 SET status = 'approved', decided_at = $1
		 WHERE id = $2 AND status = 'pending'
		 RETURNING file_id`,
		decidedAt, toPgUUID(requestID),
	).Scan(&fileID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ShareRecord{}, repository.ErrConflict
		}
		return repository.ShareRecord{}, fmt.Errorf("update share_requests for approve: %w", err)
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO share_keys (share_request_id, file_id, wrapped_dek, created_at)
		 VALUES ($1, $2, $3, $4)`,
		toPgUUID(requestID), fileID, wrappedDEK, decidedAt,
	)
	if err != nil {
		return repository.ShareRecord{}, fmt.Errorf("insert share_keys: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return repository.ShareRecord{}, fmt.Errorf("commit approve tx: %w", err)
	}

	return r.GetRequestByID(ctx, requestID)
}

func (r *ShareRepo) GetKeyByRequestID(ctx context.Context, requestID uuid.UUID) (repository.ShareKey, error) {
	var (
		k       repository.ShareKey
		id, reqID, fID pgtype.UUID
	)
	err := r.pool.QueryRow(ctx,
		`SELECT id, share_request_id, file_id, wrapped_dek, created_at
		 FROM share_keys
		 WHERE share_request_id = $1`,
		toPgUUID(requestID),
	).Scan(&id, &reqID, &fID, &k.WrappedDEK, &k.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.ShareKey{}, repository.ErrNotFound
	}
	if err != nil {
		return repository.ShareKey{}, fmt.Errorf("get share key: %w", err)
	}
	k.ID = fromPgUUID(id)
	k.ShareRequestID = fromPgUUID(reqID)
	k.FileID = fromPgUUID(fID)
	return k, nil
}

func (r *ShareRepo) GetActiveShare(ctx context.Context, requesterID, fileID uuid.UUID) (repository.ShareRecord, repository.ShareKey, error) {
	query := `
		SELECT ` + selectShareRecordFields + `, sk.id, sk.wrapped_dek, sk.created_at
		FROM share_requests sr
		JOIN stored_files f ON f.id = sr.file_id
		JOIN users u_owner ON u_owner.id = sr.owner_id
		LEFT JOIN user_keypairs kp_owner ON kp_owner.user_id = sr.owner_id
		JOIN users u_req ON u_req.id = sr.requester_id
		LEFT JOIN user_keypairs kp_req ON kp_req.user_id = sr.requester_id
		JOIN share_keys sk ON sk.share_request_id = sr.id
		WHERE sr.requester_id = $1 AND sr.file_id = $2
		  AND sr.status = 'approved' AND sr.imported_at IS NOT NULL AND sr.revoked_at IS NULL
		ORDER BY sr.requested_at DESC
		LIMIT 1
	`
	var (
		rec                    repository.ShareRecord
		k                      repository.ShareKey
		id, fID, ownerID, reqID, skID pgtype.UUID
		decidedAt, deliveredAt, importedAt, revokedAt pgtype.Timestamptz
	)

	err := r.pool.QueryRow(ctx, query, toPgUUID(requesterID), toPgUUID(fileID)).Scan(
		&id, &fID, &rec.FileName,
		&ownerID, &rec.OwnerUsername, &rec.OwnerFingerprint,
		&reqID, &rec.RequesterUsername, &rec.RequesterFingerprint,
		&rec.Status, &rec.Note,
		&rec.RequestedAt, &decidedAt, &deliveredAt, &importedAt, &revokedAt,
		&skID, &k.WrappedDEK, &k.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.ShareRecord{}, repository.ShareKey{}, repository.ErrNotFound
	}
	if err != nil {
		return repository.ShareRecord{}, repository.ShareKey{}, fmt.Errorf("get active share: %w", err)
	}

	rec.ID = fromPgUUID(id)
	rec.FileID = fromPgUUID(fID)
	rec.OwnerID = fromPgUUID(ownerID)
	rec.RequesterID = fromPgUUID(reqID)
	if decidedAt.Valid {
		t := decidedAt.Time
		rec.DecidedAt = &t
	}
	if deliveredAt.Valid {
		t := deliveredAt.Time
		rec.DeliveredAt = &t
	}
	if importedAt.Valid {
		t := importedAt.Time
		rec.ImportedAt = &t
	}
	if revokedAt.Valid {
		t := revokedAt.Time
		rec.RevokedAt = &t
	}

	k.ID = fromPgUUID(skID)
	k.ShareRequestID = rec.ID
	k.FileID = rec.FileID

	return rec, k, nil
}

func (r *ShareRepo) GetPendingCountsByOwner(ctx context.Context, ownerID uuid.UUID) (map[uuid.UUID]int, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT file_id, COUNT(*)
		 FROM share_requests
		 WHERE owner_id = $1 AND status = 'pending'
		 GROUP BY file_id`,
		toPgUUID(ownerID),
	)
	if err != nil {
		return nil, fmt.Errorf("get pending counts: %w", err)
	}
	defer rows.Close()

	counts := make(map[uuid.UUID]int)
	for rows.Next() {
		var (
			fID pgtype.UUID
			c   int
		)
		if err := rows.Scan(&fID, &c); err != nil {
			return nil, fmt.Errorf("scan pending counts: %w", err)
		}
		counts[fromPgUUID(fID)] = c
	}
	return counts, rows.Err()
}

func (r *ShareRepo) GetRequesterShares(ctx context.Context, requesterID uuid.UUID) ([]repository.ShareRecord, error) {
	query := "SELECT " + selectShareRecordFields + " WHERE sr.requester_id = $1 ORDER BY sr.requested_at DESC"
	rows, err := r.pool.Query(ctx, query, toPgUUID(requesterID))
	if err != nil {
		return nil, fmt.Errorf("get requester shares: %w", err)
	}
	defer rows.Close()

	var list []repository.ShareRecord
	for rows.Next() {
		rec, err := scanShareRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("scan requester share: %w", err)
		}
		list = append(list, rec)
	}
	return list, rows.Err()
}
