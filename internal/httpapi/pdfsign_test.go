package httpapi_test

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/audit"
	"github.com/ilhmpbta/CypherSecurity/internal/config"
	"github.com/ilhmpbta/CypherSecurity/internal/crypto/production"
	"github.com/ilhmpbta/CypherSecurity/internal/files"
	"github.com/ilhmpbta/CypherSecurity/internal/httpapi"
	"github.com/ilhmpbta/CypherSecurity/internal/keys"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
	"github.com/ilhmpbta/CypherSecurity/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type memoryFileRepo struct {
	items map[uuid.UUID]repository.File
}

func newMemoryFileRepo() *memoryFileRepo {
	return &memoryFileRepo{items: make(map[uuid.UUID]repository.File)}
}
func (m *memoryFileRepo) Create(ctx context.Context, f repository.File) (repository.File, error) {
	m.items[f.ID] = f
	return f, nil
}
func (m *memoryFileRepo) GetByIDForOwner(ctx context.Context, id, ownerID uuid.UUID) (repository.File, error) {
	f, ok := m.items[id]
	if !ok || f.OwnerID != ownerID {
		return repository.File{}, repository.ErrNotFound
	}
	return f, nil
}
func (m *memoryFileRepo) ListByOwner(ctx context.Context, ownerID uuid.UUID) ([]repository.File, error) {
	var list []repository.File
	for _, f := range m.items {
		if f.OwnerID == ownerID {
			list = append(list, f)
		}
	}
	return list, nil
}
func (m *memoryFileRepo) DeleteByOwner(ctx context.Context, id, ownerID uuid.UUID) error {
	f, ok := m.items[id]
	if !ok || f.OwnerID != ownerID {
		return repository.ErrNotFound
	}
	delete(m.items, id)
	return nil
}
func (m *memoryFileRepo) UpdateForOwner(ctx context.Context, f repository.File) (repository.File, error) {
	existing, ok := m.items[f.ID]
	if !ok || existing.OwnerID != f.OwnerID {
		return repository.File{}, repository.ErrNotFound
	}
	m.items[f.ID] = f
	return f, nil
}

type memoryAuditRepo struct {
	events []repository.AuditEvent
}

func (a *memoryAuditRepo) Insert(ctx context.Context, e repository.AuditEvent) error {
	a.events = append(a.events, e)
	return nil
}
func (a *memoryAuditRepo) ListByActor(ctx context.Context, actorID uuid.UUID, limit int) ([]repository.AuditEvent, error) {
	var res []repository.AuditEvent
	for _, e := range a.events {
		if e.ActorID != nil && *e.ActorID == actorID {
			res = append(res, e)
		}
	}
	return res, nil
}
func (a *memoryAuditRepo) ListAll(ctx context.Context, limit int) ([]repository.AuditEvent, error) {
	return a.events, nil
}

type testSessionStore struct {
	sessions map[string]*repository.Session
	wrapKeys map[uuid.UUID][]byte
	users    map[uuid.UUID]repository.User
}

func (s *testSessionStore) Lookup(ctx context.Context, token string) (*repository.Session, error) {
	sess, ok := s.sessions[token]
	if !ok || time.Now().After(sess.ExpiresAt) {
		return nil, repository.ErrNotFound
	}
	return sess, nil
}

func (s *testSessionStore) GetWrapKey(sessionID uuid.UUID) []byte {
	return s.wrapKeys[sessionID]
}

type testUserRepo struct {
	users map[uuid.UUID]repository.User
}

func (u *testUserRepo) GetByUsername(ctx context.Context, username string) (repository.User, error) {
	for _, usr := range u.users {
		if usr.Username == username {
			return usr, nil
		}
	}
	return repository.User{}, repository.ErrNotFound
}
func (u *testUserRepo) GetByID(ctx context.Context, id uuid.UUID) (repository.User, error) {
	usr, ok := u.users[id]
	if !ok {
		return repository.User{}, repository.ErrNotFound
	}
	return usr, nil
}
func (u *testUserRepo) Create(ctx context.Context, username, passwordHash string) (repository.User, error) {
	usr := repository.User{ID: uuid.New(), Username: username, CreatedAt: time.Now()}
	u.users[usr.ID] = usr
	return usr, nil
}

func generateValidTestPDFBytes() []byte {
	// A minimal valid PDF structure for testing
	pdf := "%PDF-1.4\n" +
		"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
		"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n" +
		"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n" +
		"xref\n0 4\n" +
		"0000000000 65535 f \n" +
		"0000000009 00000 n \n" +
		"0000000058 00000 n \n" +
		"0000000115 00000 n \n" +
		"trailer\n<< /Size 4 /Root 1 0 R >>\n" +
		"startxref\n185\n%%EOF\n"
	return []byte(pdf)
}

func setupTestEnvironment(t *testing.T) (http.Handler, uuid.UUID, string, *keys.Fake, *memoryAuditRepo) {
	tmpDir := t.TempDir()
	fs, err := storage.NewFS(tmpDir)
	require.NoError(t, err)

	kekBytes := make([]byte, 32)
	km, err := production.New(map[int][]byte{1: kekBytes})
	require.NoError(t, err)

	fileRepo := newMemoryFileRepo()
	auditRepo := &memoryAuditRepo{}
	auditLogger := audit.NewLogger(auditRepo)
	keysSvc := keys.NewFake()

	fileSvc := files.NewService(fileRepo, fs, km, auditLogger, files.WithKeysService(keysSvc))

	userID := uuid.New()
	user := repository.User{ID: userID, Username: "owner", CreatedAt: time.Now()}
	userRepo := &testUserRepo{users: map[uuid.UUID]repository.User{userID: user}}

	sessionID := uuid.New()
	token := "valid-session-token"
	wrapKey := []byte("32-byte-secret-wrap-key-for-test!!")

	sessStore := &testSessionStore{
		sessions: map[string]*repository.Session{
			token: {ID: sessionID, UserID: userID, ExpiresAt: time.Now().Add(time.Hour)},
		},
		wrapKeys: map[uuid.UUID][]byte{
			sessionID: wrapKey,
		},
		users: userRepo.users,
	}

	router := httpapi.NewRouter(httpapi.Deps{
		AuthSvc:      &fakeAuthService{},
		FileSvc:      fileSvc,
		AuditSvc:     auditLogger,
		KeysSvc:      keysSvc,
		UserRepo:     userRepo,
		SessionStore: sessStore,
		Config:       &config.Config{SecureCookies: false},
	})

	return router, userID, token, keysSvc, auditRepo
}

func getCSRFToken(t *testing.T, router http.Handler, token string) string {
	req, _ := http.NewRequest("GET", "/api/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: token})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	for _, c := range rec.Result().Cookies() {
		if c.Name == "csrf_token" {
			return c.Value
		}
	}
	return ""
}

func uploadTestPDF(t *testing.T, router http.Handler, token string, pdfBytes []byte, filename string) string {
	csrf := getCSRFToken(t, router, token)

	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	part, err := mw.CreateFormFile("file", filename)
	require.NoError(t, err)
	_, err = part.Write(pdfBytes)
	require.NoError(t, err)
	require.NoError(t, mw.Close())

	req, _ := http.NewRequest("POST", "/api/files", body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: "session_id", Value: token})
	if csrf != "" {
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
		req.Header.Set("X-CSRF-Token", csrf)
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)

	// parse ID from response
	// simple regex or unmarshal json
	return rec.Body.String()
}

func TestPDFSignAndVerifyEndToEnd(t *testing.T) {
	router, _, token, _, auditRepo := setupTestEnvironment(t)
	pdfBytes := generateValidTestPDFBytes()

	// Upload PDF
	csrf := getCSRFToken(t, router, token)
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	h := make(map[string][]string)
	h["Content-Disposition"] = []string{`form-data; name="file"; filename="test.pdf"`}
	h["Content-Type"] = []string{"application/pdf"}
	part, err := mw.CreatePart(h)
	require.NoError(t, err)
	_, _ = part.Write(pdfBytes)
	_ = mw.Close()

	req, _ := http.NewRequest("POST", "/api/files", body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: "session_id", Value: token})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	req.Header.Set("X-CSRF-Token", csrf)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)

	// extract file ID from response body (e.g. {"id":"uuid",...})
	respStr := rec.Body.String()
	require.Contains(t, respStr, "id")
	// Let's get file list to find the ID
	reqList, _ := http.NewRequest("GET", "/api/files", nil)
	reqList.AddCookie(&http.Cookie{Name: "session_id", Value: token})
	recList := httptest.NewRecorder()
	router.ServeHTTP(recList, reqList)
	require.Equal(t, http.StatusOK, recList.Code)

	// Parse file ID (we know there's 1 file)
	// Or we can query fileRepo directly in test setup or parse json.
	// Let's parse JSON or extract ID string.
	// For simplicity, let's extract UUID from response string.
	fileUUIDRegex := uuid.MustParse(extractUUID(respStr))

	// 1. Sign PDF (POST /api/files/{id}/sign)
	reqSign, _ := http.NewRequest("POST", "/api/files/"+fileUUIDRegex.String()+"/sign", nil)
	reqSign.AddCookie(&http.Cookie{Name: "session_id", Value: token})
	reqSign.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	reqSign.Header.Set("X-CSRF-Token", csrf)
	recSign := httptest.NewRecorder()
	router.ServeHTTP(recSign, reqSign)
	require.Equal(t, http.StatusOK, recSign.Code)
	require.Contains(t, recSign.Body.String(), "signatures")

	// 2. Verify PDF (GET /api/files/{id}/verify)
	reqVerify, _ := http.NewRequest("GET", "/api/files/"+fileUUIDRegex.String()+"/verify", nil)
	reqVerify.AddCookie(&http.Cookie{Name: "session_id", Value: token})
	recVerify := httptest.NewRecorder()
	router.ServeHTTP(recVerify, reqVerify)
	require.Equal(t, http.StatusOK, recVerify.Code)
	require.Contains(t, recVerify.Body.String(), `"valid":true`)

	// 3. Sign twice (signing already signed PDF produces two independent signatures)
	reqSign2, _ := http.NewRequest("POST", "/api/files/"+fileUUIDRegex.String()+"/sign", nil)
	reqSign2.AddCookie(&http.Cookie{Name: "session_id", Value: token})
	reqSign2.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	reqSign2.Header.Set("X-CSRF-Token", csrf)
	recSign2 := httptest.NewRecorder()
	router.ServeHTTP(recSign2, reqSign2)
	require.Equal(t, http.StatusOK, recSign2.Code)

	recVerify2 := httptest.NewRecorder()
	router.ServeHTTP(recVerify2, reqVerify)
	require.Equal(t, http.StatusOK, recVerify2.Code)
	require.Contains(t, recVerify2.Body.String(), `"valid":true`)

	// Check audit events emitted: pdf.signed and pdf.verified
	actions := make(map[string]bool)
	for _, e := range auditRepo.events {
		actions[e.Action] = true
		// Verify no sensitive keys leaked in metadata
		for k := range e.Metadata {
			assert.NotContains(t, k, "wrap")
			assert.NotContains(t, k, "dek")
			assert.NotContains(t, k, "private")
		}
	}
	assert.True(t, actions["pdf.signed"])
	assert.True(t, actions["pdf.verified"])
}

func TestPDFSignErrorsAndAccessControl(t *testing.T) {
	router, _, token, _, _ := setupTestEnvironment(t)
	csrf := getCSRFToken(t, router, token)

	// Upload non-PDF file (e.g. valid JPEG image)
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	h := make(map[string][]string)
	h["Content-Disposition"] = []string{`form-data; name="file"; filename="test.jpg"`}
	h["Content-Type"] = []string{"image/jpeg"}
	part, err := mw.CreatePart(h)
	require.NoError(t, err)
	_, _ = part.Write([]byte("\xff\xd8\xff\xe0 some jpeg content"))
	_ = mw.Close()

	req, _ := http.NewRequest("POST", "/api/files", body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: "session_id", Value: token})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	req.Header.Set("X-CSRF-Token", csrf)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)
	fileUUID := uuid.MustParse(extractUUID(rec.Body.String()))

	// Non-PDF sign -> 400 invalid_content_type
	reqSign, _ := http.NewRequest("POST", "/api/files/"+fileUUID.String()+"/sign", nil)
	reqSign.AddCookie(&http.Cookie{Name: "session_id", Value: token})
	reqSign.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	reqSign.Header.Set("X-CSRF-Token", csrf)
	recSign := httptest.NewRecorder()
	router.ServeHTTP(recSign, reqSign)
	assert.Equal(t, http.StatusBadRequest, recSign.Code)
	assert.Contains(t, recSign.Body.String(), "invalid_content_type")

	// 404 not found for sign/verify on non-existent file
	reqSign404, _ := http.NewRequest("POST", "/api/files/"+uuid.New().String()+"/sign", nil)
	reqSign404.AddCookie(&http.Cookie{Name: "session_id", Value: token})
	reqSign404.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	reqSign404.Header.Set("X-CSRF-Token", csrf)
	recSign404 := httptest.NewRecorder()
	router.ServeHTTP(recSign404, reqSign404)
	assert.Equal(t, http.StatusNotFound, recSign404.Code)
}

func TestPDFSign_LockedSession(t *testing.T) {
	tmpDir := t.TempDir()
	fs, err := storage.NewFS(tmpDir)
	require.NoError(t, err)

	kekBytes := make([]byte, 32)
	km, err := production.New(map[int][]byte{1: kekBytes})
	require.NoError(t, err)

	fileRepo := newMemoryFileRepo()
	auditLogger := audit.NewLogger(&memoryAuditRepo{})
	keysSvc := keys.NewFake()
	fileSvc := files.NewService(fileRepo, fs, km, auditLogger, files.WithKeysService(keysSvc))

	userID := uuid.New()
	user := repository.User{ID: userID, Username: "owner", CreatedAt: time.Now()}
	userRepo := &testUserRepo{users: map[uuid.UUID]repository.User{userID: user}}

	sessionID := uuid.New()
	token := "locked-session-token"
	// No wrapKey in wrapKeys (locked session)

	sessStore := &testSessionStore{
		sessions: map[string]*repository.Session{
			token: {ID: sessionID, UserID: userID, ExpiresAt: time.Now().Add(time.Hour)},
		},
		wrapKeys: map[uuid.UUID][]byte{},
		users:    userRepo.users,
	}

	router := httpapi.NewRouter(httpapi.Deps{
		AuthSvc:      &fakeAuthService{},
		FileSvc:      fileSvc,
		AuditSvc:     auditLogger,
		KeysSvc:      keysSvc,
		UserRepo:     userRepo,
		SessionStore: sessStore,
		Config:       &config.Config{SecureCookies: false},
	})

	pdfBytes := generateValidTestPDFBytes()
	csrf := getCSRFToken(t, router, token)

	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	h := make(map[string][]string)
	h["Content-Disposition"] = []string{`form-data; name="file"; filename="test.pdf"`}
	h["Content-Type"] = []string{"application/pdf"}
	part, _ := mw.CreatePart(h)
	_, _ = part.Write(pdfBytes)
	_ = mw.Close()

	req, _ := http.NewRequest("POST", "/api/files", body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: "session_id", Value: token})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	req.Header.Set("X-CSRF-Token", csrf)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)
	fileUUID := uuid.MustParse(extractUUID(rec.Body.String()))

	// Sign with locked session -> 401 reauth_required
	reqSign, _ := http.NewRequest("POST", "/api/files/"+fileUUID.String()+"/sign", nil)
	reqSign.AddCookie(&http.Cookie{Name: "session_id", Value: token})
	reqSign.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	reqSign.Header.Set("X-CSRF-Token", csrf)
	recSign := httptest.NewRecorder()
	router.ServeHTTP(recSign, reqSign)
	assert.Equal(t, http.StatusUnauthorized, recSign.Code)
	assert.Contains(t, recSign.Body.String(), "reauth_required")
}

func TestPDFSign_NonOwnerForbidden(t *testing.T) {
	tmpDir := t.TempDir()
	fs, err := storage.NewFS(tmpDir)
	require.NoError(t, err)

	kekBytes := make([]byte, 32)
	km, err := production.New(map[int][]byte{1: kekBytes})
	require.NoError(t, err)

	fileRepo := newMemoryFileRepo()
	auditLogger := audit.NewLogger(&memoryAuditRepo{})
	keysSvc := keys.NewFake()
	fileSvc := files.NewService(fileRepo, fs, km, auditLogger, files.WithKeysService(keysSvc))

	ownerID := uuid.New()
	otherID := uuid.New()
	ownerUser := repository.User{ID: ownerID, Username: "owner", CreatedAt: time.Now()}
	otherUser := repository.User{ID: otherID, Username: "other", CreatedAt: time.Now()}
	userRepo := &testUserRepo{users: map[uuid.UUID]repository.User{ownerID: ownerUser, otherID: otherUser}}

	ownerSessID := uuid.New()
	otherSessID := uuid.New()
	ownerToken := "owner-token"
	otherToken := "other-token"
	wrapKey := []byte("32-byte-secret-wrap-key-for-test!!")

	sessStore := &testSessionStore{
		sessions: map[string]*repository.Session{
			ownerToken: {ID: ownerSessID, UserID: ownerID, ExpiresAt: time.Now().Add(time.Hour)},
			otherToken: {ID: otherSessID, UserID: otherID, ExpiresAt: time.Now().Add(time.Hour)},
		},
		wrapKeys: map[uuid.UUID][]byte{
			ownerSessID: wrapKey,
			otherSessID: wrapKey,
		},
		users: userRepo.users,
	}

	router := httpapi.NewRouter(httpapi.Deps{
		AuthSvc:      &fakeAuthService{},
		FileSvc:      fileSvc,
		AuditSvc:     auditLogger,
		KeysSvc:      keysSvc,
		UserRepo:     userRepo,
		SessionStore: sessStore,
		Config:       &config.Config{SecureCookies: false},
	})

	pdfBytes := generateValidTestPDFBytes()
	csrfOwner := getCSRFToken(t, router, ownerToken)

	// Owner uploads file
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	h := make(map[string][]string)
	h["Content-Disposition"] = []string{`form-data; name="file"; filename="test.pdf"`}
	h["Content-Type"] = []string{"application/pdf"}
	part, _ := mw.CreatePart(h)
	_, _ = part.Write(pdfBytes)
	_ = mw.Close()

	req, _ := http.NewRequest("POST", "/api/files", body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: "session_id", Value: ownerToken})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfOwner})
	req.Header.Set("X-CSRF-Token", csrfOwner)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)
	fileUUID := uuid.MustParse(extractUUID(rec.Body.String()))

	// Other user tries to sign -> 404 (GetByIDForOwner restricts to owner)
	csrfOther := getCSRFToken(t, router, otherToken)
	reqSign, _ := http.NewRequest("POST", "/api/files/"+fileUUID.String()+"/sign", nil)
	reqSign.AddCookie(&http.Cookie{Name: "session_id", Value: otherToken})
	reqSign.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfOther})
	reqSign.Header.Set("X-CSRF-Token", csrfOther)
	recSign := httptest.NewRecorder()
	router.ServeHTTP(recSign, reqSign)
	assert.Equal(t, http.StatusNotFound, recSign.Code)
}

func extractUUID(body string) string {
	// find `"id":"..."`
	idx := bytes.Index([]byte(body), []byte(`"id":"`))
	if idx == -1 {
		return uuid.New().String()
	}
	start := idx + 6
	if start+36 > len(body) {
		return uuid.New().String()
	}
	return body[start : start+36]
}
