package httpapi_test

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/config"
	"github.com/ilhmpbta/CypherSecurity/internal/httpapi"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
	"github.com/stretchr/testify/assert"
)

type fakeFileService struct {
	uploadFn   func(ctx context.Context, ownerID uuid.UUID, reader io.Reader, contentType, originalName string) (repository.File, error)
	listFn     func(ctx context.Context, ownerID uuid.UUID) ([]repository.File, error)
	downloadFn func(ctx context.Context, id, ownerID uuid.UUID) (io.ReadCloser, repository.File, error)
	deleteFn   func(ctx context.Context, id, ownerID uuid.UUID) error
}

func (f *fakeFileService) Upload(ctx context.Context, ownerID uuid.UUID, r io.Reader, ct, name string) (repository.File, error) {
	if f.uploadFn != nil {
		return f.uploadFn(ctx, ownerID, r, ct, name)
	}
	return repository.File{}, nil
}
func (f *fakeFileService) List(ctx context.Context, ownerID uuid.UUID) ([]repository.File, error) {
	if f.listFn != nil {
		return f.listFn(ctx, ownerID)
	}
	return nil, nil
}
func (f *fakeFileService) Download(ctx context.Context, id, ownerID uuid.UUID) (io.ReadCloser, repository.File, error) {
	if f.downloadFn != nil {
		return f.downloadFn(ctx, id, ownerID)
	}
	return nil, repository.File{}, repository.ErrNotFound
}
func (f *fakeFileService) Delete(ctx context.Context, id, ownerID uuid.UUID) error {
	if f.deleteFn != nil {
		return f.deleteFn(ctx, id, ownerID)
	}
	return nil
}

type fakeRecordService struct {
	listFn   func(ctx context.Context, ownerID uuid.UUID) ([]repository.PersonalRecord, error)
	createFn func(ctx context.Context, ownerID uuid.UUID, dataType string, payload map[string]any) (repository.PersonalRecord, error)
}

func (f *fakeRecordService) List(ctx context.Context, ownerID uuid.UUID) ([]repository.PersonalRecord, error) {
	if f.listFn != nil {
		return f.listFn(ctx, ownerID)
	}
	return nil, nil
}
func (f *fakeRecordService) Create(ctx context.Context, ownerID uuid.UUID, dataType string, payload map[string]any) (repository.PersonalRecord, error) {
	if f.createFn != nil {
		return f.createFn(ctx, ownerID, dataType, payload)
	}
	return repository.PersonalRecord{}, nil
}
func (f *fakeRecordService) Update(ctx context.Context, id, ownerID uuid.UUID, dataType string, payload map[string]any) (repository.PersonalRecord, error) {
	return repository.PersonalRecord{}, nil
}
func (f *fakeRecordService) Delete(ctx context.Context, id, ownerID uuid.UUID) error {
	return nil
}

type fakeAuditService struct {
	listFn func(ctx context.Context, actorID uuid.UUID, limit int) ([]repository.AuditEvent, error)
}

func (f *fakeAuditService) ListByActor(ctx context.Context, actorID uuid.UUID, limit int) ([]repository.AuditEvent, error) {
	if f.listFn != nil {
		return f.listFn(ctx, actorID, limit)
	}
	return nil, nil
}

type fakeSessionStoreForFiles struct {
	sess *repository.Session
	err  error
}

func (f *fakeSessionStoreForFiles) Lookup(ctx context.Context, token string) (*repository.Session, error) {
	return f.sess, f.err
}

type fakeUserRepoForFiles struct {
	user repository.User
	err  error
}

func (f *fakeUserRepoForFiles) GetByUsername(ctx context.Context, username string) (repository.User, error) {
	return f.user, f.err
}
func (f *fakeUserRepoForFiles) GetByID(ctx context.Context, id uuid.UUID) (repository.User, error) {
	return f.user, f.err
}
func (f *fakeUserRepoForFiles) Create(ctx context.Context, u, h string) (repository.User, error) {
	return repository.User{}, nil
}

type fakeAuthService struct{}

func (f *fakeAuthService) Register(ctx context.Context, u, p string) (repository.User, error) {
	return repository.User{}, nil
}
func (f *fakeAuthService) Login(ctx context.Context, u, p, ip string) (string, error) {
	return "", nil
}
func (f *fakeAuthService) Logout(ctx context.Context, token string) error {
	return nil
}

func TestFilesDownloadExistenceLeakPrevention(t *testing.T) {
	svc := &fakeFileService{
		downloadFn: func(ctx context.Context, id, ownerID uuid.UUID) (io.ReadCloser, repository.File, error) {
			return nil, repository.File{}, repository.ErrNotFound
		},
	}

	userID := uuid.New()
	router := httpapi.NewRouter(httpapi.Deps{
		AuthSvc: &fakeAuthService{},
		FileSvc: svc,
		UserRepo: &fakeUserRepoForFiles{
			user: repository.User{ID: userID, Username: "test"},
		},
		SessionStore: &fakeSessionStoreForFiles{
			sess: &repository.Session{ID: uuid.New(), UserID: userID, ExpiresAt: time.Now().Add(time.Hour)},
		},
		Config: &config.Config{},
	})

	req, _ := http.NewRequest("GET", "/api/files/"+uuid.New().String()+"/download", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "token"})

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// Assert 404 (NOT 403)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.NotEqual(t, http.StatusForbidden, rec.Code)
}

func TestFilesListUnauthenticated(t *testing.T) {
	router := httpapi.NewRouter(httpapi.Deps{
		AuthSvc:      &fakeAuthService{},
		FileSvc:      &fakeFileService{},
		UserRepo:     &fakeUserRepoForFiles{},
		SessionStore: &fakeSessionStoreForFiles{err: repository.ErrNotFound},
		Config:       &config.Config{},
	})

	req, _ := http.NewRequest("GET", "/api/files", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRecordsListUnauthenticated(t *testing.T) {
	router := httpapi.NewRouter(httpapi.Deps{
		AuthSvc:      &fakeAuthService{},
		RecordSvc:    &fakeRecordService{},
		UserRepo:     &fakeUserRepoForFiles{},
		SessionStore: &fakeSessionStoreForFiles{err: repository.ErrNotFound},
		Config:       &config.Config{},
	})

	req, _ := http.NewRequest("GET", "/api/records", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAuditListUnauthenticated(t *testing.T) {
	router := httpapi.NewRouter(httpapi.Deps{
		AuthSvc:      &fakeAuthService{},
		AuditSvc:     &fakeAuditService{},
		UserRepo:     &fakeUserRepoForFiles{},
		SessionStore: &fakeSessionStoreForFiles{err: repository.ErrNotFound},
		Config:       &config.Config{},
	})

	req, _ := http.NewRequest("GET", "/api/audit", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestFilesUploadOversized(t *testing.T) {
	userID := uuid.New()
	router := httpapi.NewRouter(httpapi.Deps{
		AuthSvc: &fakeAuthService{},
		FileSvc: &fakeFileService{},
		UserRepo: &fakeUserRepoForFiles{
			user: repository.User{ID: userID, Username: "test"},
		},
		SessionStore: &fakeSessionStoreForFiles{
			sess: &repository.Session{ID: uuid.New(), UserID: userID, ExpiresAt: time.Now().Add(time.Hour)},
		},
		Config: &config.Config{
			MaxUploadBytes: 10, // very small limit for test
		},
	})

	// Get CSRF cookie first
	reqMe, _ := http.NewRequest("GET", "/api/auth/me", nil)
	recMe := httptest.NewRecorder()
	router.ServeHTTP(recMe, reqMe)

	var csrfCookie *http.Cookie
	for _, c := range recMe.Result().Cookies() {
		if c.Name == "csrf_token" {
			csrfCookie = c
		}
	}

	// Build a valid multipart body that exceeds 10 bytes
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	part, _ := mw.CreateFormFile("file", "big.txt")
	_, _ = part.Write(make([]byte, 100)) // 100 bytes > 10 bytes limit
	_ = mw.Close()

	reqPost, _ := http.NewRequest("POST", "/api/files", body)
	reqPost.Header.Set("Content-Type", mw.FormDataContentType())
	reqPost.AddCookie(&http.Cookie{Name: "session_id", Value: "token"})
	if csrfCookie != nil {
		reqPost.AddCookie(csrfCookie)
		reqPost.Header.Set("X-CSRF-Token", csrfCookie.Value)
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, reqPost)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}

func TestFilesUploadSuccess(t *testing.T) {
	fileID := uuid.New()
	userID := uuid.New()
	svc := &fakeFileService{
		uploadFn: func(ctx context.Context, ownerID uuid.UUID, r io.Reader, ct, name string) (repository.File, error) {
			return repository.File{
				ID:            fileID,
				OriginalName:  name,
				ContentType:   ct,
				PlaintextSize: 11,
				CreatedAt:     time.Now(),
			}, nil
		},
	}

	router := httpapi.NewRouter(httpapi.Deps{
		AuthSvc: &fakeAuthService{},
		FileSvc: svc,
		UserRepo: &fakeUserRepoForFiles{
			user: repository.User{ID: userID, Username: "test"},
		},
		SessionStore: &fakeSessionStoreForFiles{
			sess: &repository.Session{ID: uuid.New(), UserID: userID, ExpiresAt: time.Now().Add(time.Hour)},
		},
		Config: &config.Config{},
	})

	// First get me endpoint to get CSRF cookie
	reqMe, _ := http.NewRequest("GET", "/api/auth/me", nil)
	recMe := httptest.NewRecorder()
	router.ServeHTTP(recMe, reqMe)

	var csrfCookie *http.Cookie
	for _, c := range recMe.Result().Cookies() {
		if c.Name == "csrf_token" {
			csrfCookie = c
		}
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", "test.txt")
	_, _ = part.Write([]byte("hello world"))
	_ = writer.Close()

	reqPost, _ := http.NewRequest("POST", "/api/files", body)
	reqPost.Header.Set("Content-Type", writer.FormDataContentType())
	reqPost.AddCookie(&http.Cookie{Name: "session_id", Value: "token"})
	if csrfCookie != nil {
		reqPost.AddCookie(csrfCookie)
		reqPost.Header.Set("X-CSRF-Token", csrfCookie.Value)
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, reqPost)

	assert.Equal(t, http.StatusCreated, rec.Code)
}
