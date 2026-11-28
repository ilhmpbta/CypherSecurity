package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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
	"github.com/ilhmpbta/CypherSecurity/internal/sharing"
	"github.com/ilhmpbta/CypherSecurity/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type userClient struct {
	user     repository.User
	token    string
	csrf     string
	keysSess keys.Session
}

func (c *userClient) newRequest(method, path string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, path, body)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: c.token})
	if c.csrf != "" {
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: c.csrf})
		if method != http.MethodGet && method != http.MethodHead {
			req.Header.Set("X-CSRF-Token", c.csrf)
		}
	}
	return req
}

func setupSharesE2EEnvironment(t *testing.T) (http.Handler, *userClient, *userClient, *keys.Fake) {
	tmpDir := t.TempDir()
	fs, err := storage.NewFS(tmpDir)
	require.NoError(t, err)

	kekBytes := bytes.Repeat([]byte{0x77}, 32)
	km, err := production.New(map[int][]byte{1: kekBytes})
	require.NoError(t, err)

	fileRepo := newMemoryFileRepo()
	auditRepo := &memoryAuditRepo{}
	auditLogger := audit.NewLogger(auditRepo)
	keysFake := keys.NewFake()

	aliceID := uuid.New()
	bobID := uuid.New()
	aliceUser := repository.User{ID: aliceID, Username: "alice", CreatedAt: time.Now()}
	bobUser := repository.User{ID: bobID, Username: "bob", CreatedAt: time.Now()}
	userRepo := &testUserRepo{users: map[uuid.UUID]repository.User{
		aliceID: aliceUser,
		bobID:   bobUser,
	}}

	shareRepo := sharing.NewFakeShareRepo(fileRepo, userRepo, nil)
	sharingSvc := sharing.NewService(shareRepo, fileRepo, km, keysFake, auditLogger)
	fileSvc := files.NewService(fileRepo, fs, km, auditLogger, files.WithKeysService(keysFake), files.WithSharingService(sharingSvc))

	aliceToken := "alice-session-token"
	bobToken := "bob-session-token"
	wrapKey := []byte("01234567890123456789012345678901")

	aliceSessID := uuid.New()
	bobSessID := uuid.New()

	sessStore := &testSessionStore{
		sessions: map[string]*repository.Session{
			aliceToken: {ID: aliceSessID, UserID: aliceID, ExpiresAt: time.Now().Add(time.Hour)},
			bobToken:   {ID: bobSessID, UserID: bobID, ExpiresAt: time.Now().Add(time.Hour)},
		},
		wrapKeys: map[uuid.UUID][]byte{
			aliceSessID: wrapKey,
			bobSessID:   wrapKey,
		},
		users: userRepo.users,
	}

	aliceKeysSess := keys.Session{UserID: aliceID, WrapKey: wrapKey}
	bobKeysSess := keys.Session{UserID: bobID, WrapKey: wrapKey}

	_, err = keysFake.EnsureForUser(context.Background(), aliceKeysSess)
	require.NoError(t, err)
	_, err = keysFake.EnsureForUser(context.Background(), bobKeysSess)
	require.NoError(t, err)

	router := httpapi.NewRouter(httpapi.Deps{
		AuthSvc:      &fakeAuthService{},
		FileSvc:      fileSvc,
		SharingSvc:   sharingSvc,
		AuditSvc:     auditLogger,
		KeysSvc:      keysFake,
		UserRepo:     userRepo,
		SessionStore: sessStore,
		Config:       &config.Config{SecureCookies: false},
	})

	aliceCSRF := getCSRFToken(t, router, aliceToken)
	bobCSRF := getCSRFToken(t, router, bobToken)

	aliceClient := &userClient{user: aliceUser, token: aliceToken, csrf: aliceCSRF, keysSess: aliceKeysSess}
	bobClient := &userClient{user: bobUser, token: bobToken, csrf: bobCSRF, keysSess: bobKeysSess}

	return router, aliceClient, bobClient, keysFake
}

func uploadTestFile(t *testing.T, router http.Handler, client *userClient, filename string, content []byte) string {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	h := make(map[string][]string)
	h["Content-Disposition"] = []string{`form-data; name="file"; filename="` + filename + `"`}
	h["Content-Type"] = []string{"application/pdf"}
	part, err := writer.CreatePart(h)
	require.NoError(t, err)
	_, err = part.Write(content)
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	req := client.newRequest(http.MethodPost, "/api/files", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var res map[string]any
	err = json.Unmarshal(w.Body.Bytes(), &res)
	require.NoError(t, err)
	return res["id"].(string)
}

func TestShares_AcceptanceFlow(t *testing.T) {
	router, alice, bob, _ := setupSharesE2EEnvironment(t)

	pdfContent := generateValidTestPDFBytes()
	fileID := uploadTestFile(t, router, alice, "confidential.pdf", pdfContent)

	// Bob list files
	t.Run("GET /api/files - Bob discovers Alice's file", func(t *testing.T) {
		req := bob.newRequest(http.MethodGet, "/api/files", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var res struct {
			Files []struct {
				ID                 string  `json:"id"`
				OriginalName       string  `json:"original_name"`
				Access             string  `json:"access"`
				MyPendingRequestID *string `json:"my_pending_request_id"`
			} `json:"files"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
		var found bool
		for _, f := range res.Files {
			if f.ID == fileID {
				found = true
				assert.Equal(t, "shared", f.Access)
				assert.Nil(t, f.MyPendingRequestID)
			}
		}
		assert.True(t, found, "Alice's file should be listed for Bob")
	})

	var shareID string

	// Bob requests access and create 201 
	t.Run("POST /api/shares - Bob requests access", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{"file_id": fileID, "note": "Please grant access"})
		req := bob.newRequest(http.MethodPost, "/api/shares", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusCreated, w.Code)

		var res map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
		assert.Equal(t, "pending", res["status"])
		shareID = res["id"].(string)
	})

	// Duplicate pending request 
	t.Run("POST /api/shares - Duplicate request returns 200 with existing row", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{"file_id": fileID, "note": "Duplicate request"})
		req := bob.newRequest(http.MethodPost, "/api/shares", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var res map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
		assert.Equal(t, shareID, res["id"])
	})

	// Non-owner cannot approve 403
	t.Run("POST /api/shares/{id}/approve - Non-owner approve returns 403", func(t *testing.T) {
		req := bob.newRequest(http.MethodPost, "/api/shares/"+shareID+"/approve", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	// Non-owner cannot export 403
	t.Run("GET /api/shares/{id}/export - Non-owner export returns 403", func(t *testing.T) {
		req := bob.newRequest(http.MethodGet, "/api/shares/"+shareID+"/export", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	// Alice approves 200
	t.Run("POST /api/shares/{id}/approve - Alice approves", func(t *testing.T) {
		req := alice.newRequest(http.MethodPost, "/api/shares/"+shareID+"/approve", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var res map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
		assert.Equal(t, "approved", res["status"])
	})

	// Alice exports 200
	var cskeyBlob []byte
	t.Run("GET /api/shares/{id}/export - Alice exports", func(t *testing.T) {
		req := alice.newRequest(http.MethodGet, "/api/shares/"+shareID+"/export", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/octet-stream", w.Header().Get("Content-Type"))

		cskeyBlob = w.Body.Bytes()
		assert.NotEmpty(t, cskeyBlob)
		assert.True(t, bytes.HasPrefix(cskeyBlob, []byte("CSKEY\x01")))
	})

	// Tampered .cskey rejected (owner signature fails) 400
	t.Run("POST /api/shares/import - Tampered cskey rejected", func(t *testing.T) {
		tampered := make([]byte, len(cskeyBlob))
		copy(tampered, cskeyBlob)
		tampered[len(tampered)-4] ^= 0xFF

		req := bob.newRequest(http.MethodPost, "/api/shares/import", bytes.NewReader(tampered))
		req.Header.Set("Content-Type", "application/octet-stream")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var res map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &res)
		assert.Equal(t, "validation_failed", res["error"])
	})

	// Import without pending request 404
	t.Run("POST /api/shares/import - Import without request returns 404", func(t *testing.T) {
		fakeReq := sharing.ShareRequest{
			ID:     uuid.New(),
			FileID: uuid.MustParse(fileID),
			Owner:  sharing.ShareIdentity{Fingerprint: "0123456789012345678901234567890123456789012345678901234567890123"},
			Requester: sharing.ShareIdentity{Fingerprint: "0123456789012345678901234567890123456789012345678901234567890123"},
		}
		dummyBlob, err := sharing.EncodeBlob(fakeReq, []byte("key"), func(d []byte) ([]byte, error) {
			return make([]byte, 256), nil
		})
		require.NoError(t, err)

		req := bob.newRequest(http.MethodPost, "/api/shares/import", bytes.NewReader(dummyBlob))
		req.Header.Set("Content-Type", "application/octet-stream")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	// Bob import valid .cskey 200 
	t.Run("POST /api/shares/import - Bob imports valid cskey", func(t *testing.T) {
		req := bob.newRequest(http.MethodPost, "/api/shares/import", bytes.NewReader(cskeyBlob))
		req.Header.Set("Content-Type", "application/octet-stream")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
	})

	// Bob download file 200
	t.Run("GET /api/files/{id}/download - Bob downloads shared file, bytes match", func(t *testing.T) {
		req := bob.newRequest(http.MethodGet, "/api/files/"+fileID+"/download", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, pdfContent, w.Body.Bytes())
	})

	// Alice revoke share 200 
	t.Run("POST /api/shares/{id}/revoke - Alice revokes access", func(t *testing.T) {
		req := alice.newRequest(http.MethodPost, "/api/shares/"+shareID+"/revoke", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
	})

	// Revoke close access and returns 403
	t.Run("GET /api/files/{id}/download - Post-revoke download returns 403", func(t *testing.T) {
		req := bob.newRequest(http.MethodGet, "/api/files/"+fileID+"/download", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

func TestShares_RejectClosesAccess(t *testing.T) {
	router, alice, bob, _ := setupSharesE2EEnvironment(t)

	pdfContent := generateValidTestPDFBytes()
	fileID := uploadTestFile(t, router, alice, "confidential2.pdf", pdfContent)

	// Bob request access
	body, _ := json.Marshal(map[string]any{"file_id": fileID})
	req := bob.newRequest(http.MethodPost, "/api/shares", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var res map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
	shareID := res["id"].(string)

	// Alice reject
	rejectReq := alice.newRequest(http.MethodPost, "/api/shares/"+shareID+"/reject", nil)
	wReject := httptest.NewRecorder()
	router.ServeHTTP(wReject, rejectReq)
	require.Equal(t, http.StatusOK, wReject.Code)

	// Reject close access
	dlReq := bob.newRequest(http.MethodGet, "/api/files/"+fileID+"/download", nil)
	wDl := httptest.NewRecorder()
	router.ServeHTTP(wDl, dlReq)
	assert.Equal(t, http.StatusForbidden, wDl.Code)
}
