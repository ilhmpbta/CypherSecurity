package files

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/crypto/production"
	"github.com/ilhmpbta/CypherSecurity/internal/keys"
	"github.com/ilhmpbta/CypherSecurity/internal/pdfsign"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
	"github.com/ilhmpbta/CypherSecurity/internal/sharing"
	"github.com/ilhmpbta/CypherSecurity/internal/storage"
)

var (
	ErrForbidden = errors.New("forbidden")
)

// AuditLogger defines the interface for recording audit events.
type AuditLogger interface {
	Log(ctx context.Context, e repository.AuditEvent) error
}

type SharingService interface {
	GetActiveShare(ctx context.Context, requesterID, fileID uuid.UUID) (*sharing.ActiveShare, error)
	GetSharingMeta(ctx context.Context, userID uuid.UUID, files []repository.File) (map[uuid.UUID]sharing.FileShareMeta, error)
}

type ListedFile struct {
	ID                   uuid.UUID  `json:"id"`
	OriginalName         string     `json:"original_name"`
	ContentType          string     `json:"content_type"`
	PlaintextSize        int64      `json:"plaintext_size"`
	CreatedAt            time.Time  `json:"created_at"`
	Access               string     `json:"access"`
	MyPendingRequestID   *uuid.UUID `json:"my_pending_request_id"`
	PendingRequestsCount int        `json:"pending_requests_count"`
	ShareState           string     `json:"share_state,omitempty"`
}

// Service orchestrates upload, download, and authorization.
type Service struct {
	repo        repository.FileRepo
	fs          *storage.FS
	km          *production.KeyManager
	keysSvc     keys.Service
	sharingSvc  SharingService
	auditLogger AuditLogger
	now         func() time.Time
}

type ServiceOption func(*Service)

func WithKeysService(keysSvc keys.Service) ServiceOption {
	return func(s *Service) {
		s.keysSvc = keysSvc
	}
}

func WithSharingService(sharingSvc SharingService) ServiceOption {
	return func(s *Service) {
		s.sharingSvc = sharingSvc
	}
}

func NewService(repo repository.FileRepo, fs *storage.FS, km *production.KeyManager, auditLogger AuditLogger, opts ...ServiceOption) *Service {
	s := &Service{
		repo:        repo,
		fs:          fs,
		km:          km,
		auditLogger: auditLogger,
		now:         time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
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
		NoncePrefix:    []byte{}, // Vestigial per new AEAD streaming contract (nonce is in the stream blob)
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

func (s *Service) OpenShared(ctx context.Context, fileID uuid.UUID, sess keys.Session) (io.ReadCloser, repository.File, error) {
	if len(sess.WrapKey) == 0 {
		return nil, repository.File{}, keys.ErrSessionLocked
	}
	if s.keysSvc == nil {
		return nil, repository.File{}, errors.New("keys service not configured")
	}
	if s.sharingSvc == nil {
		return nil, repository.File{}, ErrForbidden
	}

	file, err := s.repo.GetByID(ctx, fileID)
	if err != nil {
		return nil, repository.File{}, err
	}

	active, err := s.sharingSvc.GetActiveShare(ctx, sess.UserID, fileID)
	if err != nil {
		return nil, repository.File{}, ErrForbidden
	}

	dek, err := s.keysSvc.UnwrapForRequester(ctx, sess, active.WrappedDEK)
	if err != nil {
		return nil, repository.File{}, fmt.Errorf("unwrap dek for requester: %w", err)
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
			ActorID:  &sess.UserID,
			Action:   "files.download_shared",
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

func (s *Service) List(ctx context.Context, userID uuid.UUID) ([]ListedFile, error) {
	var (
		rawFiles []repository.File
		err      error
	)
	if s.sharingSvc != nil {
		rawFiles, err = s.repo.ListAll(ctx)
	} else {
		rawFiles, err = s.repo.ListByOwner(ctx, userID)
	}
	if err != nil {
		return nil, err
	}

	var metaMap map[uuid.UUID]sharing.FileShareMeta
	if s.sharingSvc != nil && len(rawFiles) > 0 {
		metaMap, err = s.sharingSvc.GetSharingMeta(ctx, userID, rawFiles)
		if err != nil {
			return nil, err
		}
	}

	out := make([]ListedFile, len(rawFiles))
	for i, f := range rawFiles {
		access := "owner"
		var myPendingID *uuid.UUID
		pendingCount := 0
		shareState := "none"

		if meta, ok := metaMap[f.ID]; ok {
			access = meta.Access
			myPendingID = meta.MyPendingRequestID
			pendingCount = meta.PendingRequestsCount
			shareState = meta.ShareState
		} else if f.OwnerID != userID {
			access = "shared"
		}

		out[i] = ListedFile{
			ID:                   f.ID,
			OriginalName:         f.OriginalName,
			ContentType:          f.ContentType,
			PlaintextSize:        f.PlaintextSize,
			CreatedAt:            f.CreatedAt,
			Access:               access,
			MyPendingRequestID:   myPendingID,
			PendingRequestsCount: pendingCount,
			ShareState:           shareState,
		}
	}
	return out, nil
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

func (s *Service) Sign(ctx context.Context, id uuid.UUID, keysSess keys.Session) ([]pdfsign.SignatureVerificationResult, repository.File, error) {
	if len(keysSess.WrapKey) == 0 {
		return nil, repository.File{}, keys.ErrSessionLocked
	}
	file, err := s.repo.GetByIDForOwner(ctx, id, keysSess.UserID)
	if err != nil {
		return nil, repository.File{}, err
	}

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
	pdfBytes, err := io.ReadAll(decryptR)
	_ = blobReader.Close()
	if err != nil {
		return nil, repository.File{}, err
	}

	isPDF := file.ContentType == "application/pdf" || (len(pdfBytes) >= 5 && bytes.HasPrefix(pdfBytes, []byte("%PDF-")))
	if !isPDF {
		return nil, repository.File{}, ErrInvalidContentType
	}

	if s.keysSvc == nil {
		return nil, repository.File{}, errors.New("keys service not configured")
	}

	signedPDF, err := pdfsign.SignPDF(ctx, pdfBytes, s.keysSvc, keysSess)
	if err != nil {
		return nil, repository.File{}, err
	}

	newStorageKey, err := generateStorageKey()
	if err != nil {
		return nil, repository.File{}, err
	}

	pr, pw := io.Pipe()
	cw := &countingWriter{w: pw}
	scr := &sizeCountingReader{r: bytes.NewReader(signedPDF), n: int64(len(signedPDF))}

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

	if err := s.fs.Write(newStorageKey, pr); err != nil {
		_ = pr.CloseWithError(err)
		_ = s.fs.Delete(newStorageKey)
		return nil, repository.File{}, err
	}

	oldStorageKey := file.StorageKey
	file.StorageKey = newStorageKey
	file.PlaintextSize = int64(len(signedPDF))
	file.CiphertextSize = cw.n

	updatedFile, err := s.repo.UpdateForOwner(ctx, file)
	if err != nil {
		_ = s.fs.Delete(newStorageKey)
		return nil, repository.File{}, err
	}
	_ = s.fs.Delete(oldStorageKey)

	results, err := pdfsign.VerifyPDF(ctx, signedPDF, s.keysSvc, keysSess.UserID)
	if err != nil {
		return nil, updatedFile, err
	}

	if s.auditLogger != nil {
		targetID := file.ID.String()
		sigCount := len(results)
		_ = s.auditLogger.Log(ctx, repository.AuditEvent{
			ActorID:  &keysSess.UserID,
			Action:   "pdf.signed",
			TargetID: &targetID,
			Metadata: map[string]any{
				"file_id":         file.ID.String(),
				"user_id":         keysSess.UserID.String(),
				"signature_count": sigCount,
			},
		})
	}

	return results, updatedFile, nil
}

func (s *Service) Verify(ctx context.Context, id, userID uuid.UUID) ([]pdfsign.SignatureVerificationResult, repository.File, error) {
	file, err := s.repo.GetByIDForOwner(ctx, id, userID)
	if err != nil {
		return nil, repository.File{}, err
	}

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
	pdfBytes, err := io.ReadAll(decryptR)
	_ = blobReader.Close()
	if err != nil {
		return nil, repository.File{}, err
	}

	results, err := pdfsign.VerifyPDF(ctx, pdfBytes, s.keysSvc, file.OwnerID)
	if err != nil {
		return nil, file, err
	}

	valid := false
	reason := "no_signature"
	if len(results) > 0 {
		valid = results[0].Valid
		reason = results[0].Reason
	}

	if s.auditLogger != nil {
		targetID := file.ID.String()
		_ = s.auditLogger.Log(ctx, repository.AuditEvent{
			ActorID:  &userID,
			Action:   "pdf.verified",
			TargetID: &targetID,
			Metadata: map[string]any{
				"file_id": file.ID.String(),
				"user_id": userID.String(),
				"valid":   valid,
				"reason":  reason,
			},
		})
	}

	return results, file, nil
}
