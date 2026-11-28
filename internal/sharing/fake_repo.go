package sharing

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
)

type FakeShareRepo struct {
	mu           sync.Mutex
	records      map[uuid.UUID]repository.ShareRecord
	keys         map[uuid.UUID]repository.ShareKey
	fileRepo     repository.FileRepo
	userRepo     repository.UserRepo
	keypairRepo  repository.UserKeypairRepo
}

func NewFakeShareRepo(fileRepo repository.FileRepo, userRepo repository.UserRepo, keypairRepo repository.UserKeypairRepo) *FakeShareRepo {
	return &FakeShareRepo{
		records:     make(map[uuid.UUID]repository.ShareRecord),
		keys:        make(map[uuid.UUID]repository.ShareKey),
		fileRepo:    fileRepo,
		userRepo:    userRepo,
		keypairRepo: keypairRepo,
	}
}

func (r *FakeShareRepo) populateIdentities(ctx context.Context, rec *repository.ShareRecord) {
	if r.fileRepo != nil && rec.FileName == "" {
		if f, err := r.fileRepo.GetByID(ctx, rec.FileID); err == nil {
			rec.FileName = f.OriginalName
		}
	}
	if r.userRepo != nil {
		if u, err := r.userRepo.GetByID(ctx, rec.OwnerID); err == nil {
			rec.OwnerUsername = u.Username
		}
		if u, err := r.userRepo.GetByID(ctx, rec.RequesterID); err == nil {
			rec.RequesterUsername = u.Username
		}
	}
	if r.keypairRepo != nil {
		if kp, err := r.keypairRepo.GetByUserID(ctx, rec.OwnerID); err == nil {
			rec.OwnerFingerprint = kp.Fingerprint
		}
		if kp, err := r.keypairRepo.GetByUserID(ctx, rec.RequesterID); err == nil {
			rec.RequesterFingerprint = kp.Fingerprint
		}
	}
}

func (r *FakeShareRepo) CreateRequest(ctx context.Context, req repository.ShareRecord) (repository.ShareRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if req.ID == uuid.Nil {
		req.ID = uuid.New()
	}
	if req.RequestedAt.IsZero() {
		req.RequestedAt = time.Now()
	}

	r.populateIdentities(ctx, &req)
	r.records[req.ID] = req
	return req, nil
}

func (r *FakeShareRepo) GetRequestByID(ctx context.Context, id uuid.UUID) (repository.ShareRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	rec, ok := r.records[id]
	if !ok {
		return repository.ShareRecord{}, repository.ErrNotFound
	}
	r.populateIdentities(ctx, &rec)
	return rec, nil
}

func (r *FakeShareRepo) GetPendingRequest(ctx context.Context, fileID, requesterID uuid.UUID) (repository.ShareRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, rec := range r.records {
		if rec.FileID == fileID && rec.RequesterID == requesterID && rec.Status == string(StatusPending) {
			r.populateIdentities(ctx, &rec)
			return rec, nil
		}
	}
	return repository.ShareRecord{}, repository.ErrNotFound
}

func (r *FakeShareRepo) ListInbox(ctx context.Context, ownerID uuid.UUID, status string) ([]repository.ShareRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []repository.ShareRecord
	for _, rec := range r.records {
		if rec.OwnerID == ownerID {
			if status == "" || rec.Status == status {
				r.populateIdentities(ctx, &rec)
				out = append(out, rec)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RequestedAt.After(out[j].RequestedAt)
	})
	return out, nil
}

func (r *FakeShareRepo) ListOutgoing(ctx context.Context, requesterID uuid.UUID, status string) ([]repository.ShareRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []repository.ShareRecord
	for _, rec := range r.records {
		if rec.RequesterID == requesterID {
			if status == "" || rec.Status == status {
				r.populateIdentities(ctx, &rec)
				out = append(out, rec)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RequestedAt.After(out[j].RequestedAt)
	})
	return out, nil
}

func (r *FakeShareRepo) UpdateRequest(ctx context.Context, req repository.ShareRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	existing, ok := r.records[req.ID]
	if !ok {
		return repository.ErrNotFound
	}

	// State machine transition validation
	if existing.Status != req.Status {
		if existing.Status == string(StatusPending) && (req.Status == string(StatusApproved) || req.Status == string(StatusRejected)) {
			// valid
		} else if existing.Status == string(StatusApproved) && req.Status == string(StatusRevoked) {
			// valid
		} else {
			return ErrInvalidTransition
		}
	}

	r.populateIdentities(ctx, &req)
	r.records[req.ID] = req
	return nil
}

func (r *FakeShareRepo) ApproveShare(ctx context.Context, requestID uuid.UUID, decidedAt time.Time, wrappedDEK []byte) (repository.ShareRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	rec, ok := r.records[requestID]
	if !ok {
		return repository.ShareRecord{}, repository.ErrNotFound
	}
	if rec.Status != string(StatusPending) {
		return repository.ShareRecord{}, repository.ErrConflict
	}

	rec.Status = string(StatusApproved)
	rec.DecidedAt = &decidedAt
	r.records[requestID] = rec

	k := repository.ShareKey{
		ID:             uuid.New(),
		ShareRequestID: requestID,
		FileID:         rec.FileID,
		WrappedDEK:     wrappedDEK,
		CreatedAt:      decidedAt,
	}
	r.keys[requestID] = k

	r.populateIdentities(ctx, &rec)
	return rec, nil
}

func (r *FakeShareRepo) GetKeyByRequestID(ctx context.Context, requestID uuid.UUID) (repository.ShareKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	k, ok := r.keys[requestID]
	if !ok {
		return repository.ShareKey{}, repository.ErrNotFound
	}
	return k, nil
}

func (r *FakeShareRepo) GetActiveShare(ctx context.Context, requesterID, fileID uuid.UUID) (repository.ShareRecord, repository.ShareKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var (
		foundRec repository.ShareRecord
		foundKey repository.ShareKey
		found    bool
	)

	for _, rec := range r.records {
		if rec.RequesterID == requesterID && rec.FileID == fileID &&
			rec.Status == string(StatusApproved) && rec.ImportedAt != nil && rec.RevokedAt == nil {
			k, ok := r.keys[rec.ID]
			if ok {
				if !found || rec.RequestedAt.After(foundRec.RequestedAt) {
					foundRec = rec
					foundKey = k
					found = true
				}
			}
		}
	}

	if !found {
		return repository.ShareRecord{}, repository.ShareKey{}, repository.ErrNotFound
	}

	r.populateIdentities(ctx, &foundRec)
	return foundRec, foundKey, nil
}

func (r *FakeShareRepo) GetPendingCountsByOwner(ctx context.Context, ownerID uuid.UUID) (map[uuid.UUID]int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	counts := make(map[uuid.UUID]int)
	for _, rec := range r.records {
		if rec.OwnerID == ownerID && rec.Status == string(StatusPending) {
			counts[rec.FileID]++
		}
	}
	return counts, nil
}

func (r *FakeShareRepo) GetRequesterShares(ctx context.Context, requesterID uuid.UUID) ([]repository.ShareRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []repository.ShareRecord
	for _, rec := range r.records {
		if rec.RequesterID == requesterID {
			r.populateIdentities(ctx, &rec)
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RequestedAt.After(out[j].RequestedAt)
	})
	return out, nil
}
