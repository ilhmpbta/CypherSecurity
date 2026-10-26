package files

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/crypto/production"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
	"github.com/ilhmpbta/CypherSecurity/internal/storage"
)

// AuditLogger defines the interface for recording audit events.
type AuditLogger interface {
	Log(ctx context.Context, e repository.AuditEvent) error
}

// Service orchestrates upload, download, and authorization.
type Service struct {
	repo        repository.FileRepo
	fs          *storage.FS
	km          *production.KeyManager
	auditLogger AuditLogger
	now         func() time.Time
}

func NewService(repo repository.FileRepo, fs *storage.FS, km *production.KeyManager, auditLogger AuditLogger) *Service {
	return &Service{
		repo:        repo,
		fs:          fs,
		km:          km,
		auditLogger: auditLogger,
		now:         time.Now,
	}
}

func generateStorageKey() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

type sizeCountingReader struct {
	r io.Reader
	n int64
}

func (scr *sizeCountingReader) Read(p []byte) (int, error) {
	n, err := scr.r.Read(p)
	scr.n += int64(n)
	return n, err
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.n += int64(n)
	return n, err
}

func (s *Service) Upload(ctx context.Context, ownerID uuid.UUID, r io.Reader, contentType, originalName string) (repository.File, error) {
	buf := make([]byte, 512)
	nRead, _ := io.ReadFull(r, buf)
	first512 := buf[:nRead]

	if err := ValidateContentType(contentType, first512); err != nil {
		return repository.File{}, err
	}

	storageKey, err := generateStorageKey()
	if err != nil {
		return repository.File{}, err
	}

	dek, err := s.km.GenerateDEK()
	if err != nil {
		return repository.File{}, err
	}

	wrappedDEK, _, err := s.km.Wrap(dek)
	if err != nil {
		return repository.File{}, err
	}

	fullReader := io.MultiReader(bytes.NewReader(first512), r)
	scr := &sizeCountingReader{r: fullReader}

	pr, pw := io.Pipe()
	cw := &countingWriter{w: pw}

	go func() {
		ew, err := production.NewWriter(cw, dek)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if _, err := io.Copy(ew, scr); err != nil {
			_ = ew.Close()
			_ = pw.CloseWithError(err)
			return
		}
		if err := ew.Close(); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		_ = pw.Close()
	}()

	if err := s.fs.Write(storageKey, pr); err != nil {
		_ = pr.CloseWithError(err)
		_ = s.fs.Delete(storageKey)
		return repository.File{}, err
	}

	fileRecord := repository.File{
		ID:             uuid.New(),
		OwnerID:        ownerID,
		StorageKey:     storageKey,
		OriginalName:   originalName,
		ContentType:    contentType,
		PlaintextSize:  scr.n,
		CiphertextSize: cw.n,
		AlgID:          "aes-256-gcm-stream-v1",
		WrappedDEK:     wrappedDEK,
		NoncePrefix:    nil, // Vestigial per new AEAD streaming contract (nonce is in the stream blob)
		CreatedAt:      s.now(),
	}

	saved, err := s.repo.Create(ctx, fileRecord)
	if err != nil {
		_ = s.fs.Delete(storageKey)
		return repository.File{}, err
	}

	if s.auditLogger != nil {
		targetID := saved.ID.String()
		_ = s.auditLogger.Log(ctx, repository.AuditEvent{
			ActorID:  &ownerID,
			Action:   "files.upload",
			TargetID: &targetID,
			Metadata: map[string]any{
				"original_name": originalName,
				"size":          saved.PlaintextSize,
				"content_type":  contentType,
			},
		})
	}

	return saved, nil
}

func (s *Service) Download(ctx context.Context, id, ownerID uuid.UUID) (io.ReadCloser, repository.File, error) {
	file, err := s.repo.GetByIDForOwner(ctx, id, ownerID)
	if err != nil {
		return nil, repository.File{}, err
	}

	// TODO: persist KEKVersion in repository.File and schema; using version 1 as default.
	dek, err := s.km.Unwrap(file.WrappedDEK, 1)
	if err != nil {
		return nil, repository.File{}, err
	}

	blobReader, err := s.fs.Open(file.StorageKey)
	if err != nil {
		return nil, repository.File{}, err
	}

	decryptR, err := production.NewReader(blobReader, dek)
	if err != nil {
		_ = blobReader.Close()
		return nil, repository.File{}, err
	}

	if s.auditLogger != nil {
		targetID := file.ID.String()
		_ = s.auditLogger.Log(ctx, repository.AuditEvent{
			ActorID:  &ownerID,
			Action:   "files.download",
			TargetID: &targetID,
			Metadata: map[string]any{"original_name": file.OriginalName},
		})
	}

	rc := &decryptReadCloser{
		Reader: decryptR,
		closer: blobReader,
	}

	return rc, file, nil
}

type decryptReadCloser struct {
	io.Reader
	closer io.Closer
}

func (drc *decryptReadCloser) Close() error {
	return drc.closer.Close()
}

func (s *Service) List(ctx context.Context, ownerID uuid.UUID) ([]repository.File, error) {
	return s.repo.ListByOwner(ctx, ownerID)
}

func (s *Service) Delete(ctx context.Context, id, ownerID uuid.UUID) error {
	file, err := s.repo.GetByIDForOwner(ctx, id, ownerID)
	if err != nil {
		return err
	}

	if err := s.repo.DeleteByOwner(ctx, id, ownerID); err != nil {
		return err
	}

	if err := s.fs.Delete(file.StorageKey); err != nil {
		return err
	}

	if s.auditLogger != nil {
		targetID := id.String()
		_ = s.auditLogger.Log(ctx, repository.AuditEvent{
			ActorID:  &ownerID,
			Action:   "files.delete",
			TargetID: &targetID,
			Metadata: map[string]any{"original_name": file.OriginalName},
		})
	}

	return nil
}
