package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/crypto/production"
	"github.com/ilhmpbta/CypherSecurity/internal/httpapi/middleware"
	"github.com/ilhmpbta/CypherSecurity/internal/keys"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
	"github.com/ilhmpbta/CypherSecurity/internal/sharing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type memoryFileRepoForHandlers struct {
	files map[uuid.UUID]repository.File
}

func newMemoryFileRepoForHandlers() *memoryFileRepoForHandlers {
	return &memoryFileRepoForHandlers{files: make(map[uuid.UUID]repository.File)}
}
func (m *memoryFileRepoForHandlers) Create(ctx context.Context, f repository.File) (repository.File, error) {
	m.files[f.ID] = f
	return f, nil
}
func (m *memoryFileRepoForHandlers) GetByIDForOwner(ctx context.Context, id, ownerID uuid.UUID) (repository.File, error) {
	f, ok := m.files[id]
	if !ok || f.OwnerID != ownerID {
		return repository.File{}, repository.ErrNotFound
	}
	return f, nil
}
func (m *memoryFileRepoForHandlers) GetByID(ctx context.Context, id uuid.UUID) (repository.File, error) {
	f, ok := m.files[id]
	if !ok {
		return repository.File{}, repository.ErrNotFound
	}
	return f, nil
}
func (m *memoryFileRepoForHandlers) ListByOwner(ctx context.Context, ownerID uuid.UUID) ([]repository.File, error) {
	var out []repository.File
	for _, f := range m.files {
		if f.OwnerID == ownerID {
			out = append(out, f)
		}
	}
	return out, nil
}
func (m *memoryFileRepoForHandlers) ListAll(ctx context.Context) ([]repository.File, error) {
	var out []repository.File
	for _, f := range m.files {
		out = append(out, f)
	}
	return out, nil
}
func (m *memoryFileRepoForHandlers) DeleteByOwner(ctx context.Context, id, ownerID uuid.UUID) error {
	f, ok := m.files[id]
	if !ok || f.OwnerID != ownerID {
		return repository.ErrNotFound
	}
	delete(m.files, id)
	return nil
}
func (m *memoryFileRepoForHandlers) UpdateForOwner(ctx context.Context, f repository.File) (repository.File, error) {
	existing, ok := m.files[f.ID]
	if !ok || existing.OwnerID != f.OwnerID {
		return repository.File{}, repository.ErrNotFound
	}
	m.files[f.ID] = f
	return f, nil
}

type memoryUserRepoForHandlers struct {
	users map[uuid.UUID]repository.User
}

func (m *memoryUserRepoForHandlers) Create(ctx context.Context, username, passwordHash string) (repository.User, error) {
	u := repository.User{ID: uuid.New(), Username: username, PasswordHash: passwordHash}
	m.users[u.ID] = u
	return u, nil
}
func (m *memoryUserRepoForHandlers) GetByUsername(ctx context.Context, username string) (repository.User, error) {
	for _, u := range m.users {
		if u.Username == username {
			return u, nil
		}
	}
	return repository.User{}, repository.ErrNotFound
}
func (m *memoryUserRepoForHandlers) GetByID(ctx context.Context, id uuid.UUID) (repository.User, error) {
	u, ok := m.users[id]
	if !ok {
		return repository.User{}, repository.ErrNotFound
	}
	return u, nil
}

func setupSharesHandlerTest(t *testing.T) (*SharesHandler, *sharing.Service, *memoryFileRepoForHandlers, *keys.Fake, *production.KeyManager) {
	kek := bytes.Repeat([]byte{0x42}, 32)
	km, err := production.New(map[int][]byte{1: kek})
	require.NoError(t, err)

	fileRepo := newMemoryFileRepoForHandlers()
	userRepo := &memoryUserRepoForHandlers{users: make(map[uuid.UUID]repository.User)}
	keysFake := keys.NewFake()
	shareRepo := sharing.NewFakeShareRepo(fileRepo, userRepo, nil)

	sharingSvc := sharing.NewService(shareRepo, fileRepo, km, keysFake, nil)
	handler := NewSharesHandler(sharingSvc)

	return handler, sharingSvc, fileRepo, keysFake, km
}

func withUserContext(r *http.Request, u repository.User, wrapKey []byte) *http.Request {
	sess := &repository.Session{ID: uuid.New(), UserID: u.ID}
	keysSess := keys.Session{UserID: u.ID, WrapKey: wrapKey}
	ctx := middleware.WithContextUser(r.Context(), u, sess, keysSess)
	return r.WithContext(ctx)
}

func TestSharesHandler_AcceptanceSuite(t *testing.T) {
	ctx := context.Background()
	handler, _, fileRepo, keysFake, km := setupSharesHandlerTest(t)

	alice := repository.User{ID: uuid.New(), Username: "alice"}
	bob := repository.User{ID: uuid.New(), Username: "bob"}
	wrapKey := []byte("01234567890123456789012345678901")

	_, err := keysFake.EnsureForUser(ctx, keys.Session{UserID: alice.ID, WrapKey: wrapKey})
	require.NoError(t, err)
	_, err = keysFake.EnsureForUser(ctx, keys.Session{UserID: bob.ID, WrapKey: wrapKey})
	require.NoError(t, err)

	rawDEK, err := km.GenerateDEK()
	require.NoError(t, err)
	wrappedDEK, _, err := km.Wrap(rawDEK)
	require.NoError(t, err)

	file := repository.File{
		ID:            uuid.New(),
		OwnerID:       alice.ID,
		OriginalName:  "financials.pdf",
		ContentType:   "application/pdf",
		PlaintextSize: 2048,
		WrappedDEK:    wrappedDEK,
	}
	_, err = fileRepo.Create(ctx, file)
	require.NoError(t, err)

	var shareID string

	// Bob request access and create 201 
	t.Run("POST /api/shares - B requests access", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{"file_id": file.ID, "note": "Please share"})
		req := httptest.NewRequest(http.MethodPost, "/api/shares", bytes.NewReader(body))
		req = withUserContext(req, bob, wrapKey)
		w := httptest.NewRecorder()

		handler.CreateRequest(w, req)
		require.Equal(t, http.StatusCreated, w.Code)

		var res map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &res)
		require.NoError(t, err)
		assert.Equal(t, "pending", res["status"])
		assert.Equal(t, file.ID.String(), res["file_id"])

		shareID = res["id"].(string)
	})

	// Duplicate pending request return 200
	t.Run("POST /api/shares - Duplicate pending request returns 200", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{"file_id": file.ID, "note": "Second try"})
		req := httptest.NewRequest(http.MethodPost, "/api/shares", bytes.NewReader(body))
		req = withUserContext(req, bob, wrapKey)
		w := httptest.NewRecorder()

		handler.CreateRequest(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var res map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &res)
		require.NoError(t, err)
		assert.Equal(t, shareID, res["id"])
	})

	// Non-owner cannot approve 403
	t.Run("POST /api/shares/{id}/approve - Non-owner approve returns 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/shares/"+shareID+"/approve", nil)
		req.SetPathValue("id", shareID)
		req = withUserContext(req, bob, wrapKey)
		w := httptest.NewRecorder()

		handler.Approve(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	// Non-owner cannot export 403
	t.Run("GET /api/shares/{id}/export - Non-owner export returns 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/shares/"+shareID+"/export", nil)
		req.SetPathValue("id", shareID)
		req = withUserContext(req, bob, wrapKey)
		w := httptest.NewRecorder()

		handler.Export(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	// Alice approve 200 
	t.Run("POST /api/shares/{id}/approve - Owner approves", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/shares/"+shareID+"/approve", nil)
		req.SetPathValue("id", shareID)
		req = withUserContext(req, alice, wrapKey)
		w := httptest.NewRecorder()

		handler.Approve(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var res map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &res)
		require.NoError(t, err)
		assert.Equal(t, "approved", res["status"])
	})

	// Alice export .cskey 200 
	var cskeyBlob []byte
	t.Run("GET /api/shares/{id}/export - Owner exports cskey", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/shares/"+shareID+"/export", nil)
		req.SetPathValue("id", shareID)
		req = withUserContext(req, alice, wrapKey)
		w := httptest.NewRecorder()

		handler.Export(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/octet-stream", w.Header().Get("Content-Type"))
		assert.Contains(t, w.Header().Get("Content-Disposition"), "financials.pdf.cskey")

		cskeyBlob = w.Body.Bytes()
		assert.NotEmpty(t, cskeyBlob)
		assert.True(t, bytes.HasPrefix(cskeyBlob, []byte("CSKEY\x01")))
	})

	// Tampered .cskey rejected (owner signature fails) 400
	t.Run("POST /api/shares/import - Tampered cskey rejected", func(t *testing.T) {
		tampered := make([]byte, len(cskeyBlob))
		copy(tampered, cskeyBlob)
		tampered[len(tampered)-3] ^= 0x77

		req := httptest.NewRequest(http.MethodPost, "/api/shares/import", bytes.NewReader(tampered))
		req.Header.Set("Content-Type", "application/octet-stream")
		req = withUserContext(req, bob, wrapKey)
		w := httptest.NewRecorder()

		handler.Import(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var res map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &res)
		assert.Equal(t, "validation_failed", res["error"])
	})

	// Import without pending request 404
	t.Run("POST /api/shares/import - Import without request returns 404", func(t *testing.T) {
		fakeReq := sharing.ShareRequest{
			ID:     uuid.New(),
			FileID: file.ID,
			Owner:  sharing.ShareIdentity{Fingerprint: "0123456789012345678901234567890123456789012345678901234567890123"},
			Requester: sharing.ShareIdentity{Fingerprint: "0123456789012345678901234567890123456789012345678901234567890123"},
		}
		dummyBlob, err := sharing.EncodeBlob(fakeReq, []byte("key"), func(d []byte) ([]byte, error) {
			return make([]byte, 256), nil
		})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/shares/import", bytes.NewReader(dummyBlob))
		req.Header.Set("Content-Type", "application/octet-stream")
		req = withUserContext(req, bob, wrapKey)
		w := httptest.NewRecorder()

		handler.Import(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	// Bob imports valid .cskey 200 
	t.Run("POST /api/shares/import - Valid import succeeds", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/shares/import", bytes.NewReader(cskeyBlob))
		req.Header.Set("Content-Type", "application/octet-stream")
		req = withUserContext(req, bob, wrapKey)
		w := httptest.NewRecorder()

		handler.Import(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var res map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &res)
		require.NoError(t, err)
		assert.NotNil(t, res["imported_at"])
	})

	// Reimport 200 
	t.Run("POST /api/shares/import - Idempotent re-import", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/shares/import", bytes.NewReader(cskeyBlob))
		req.Header.Set("Content-Type", "application/octet-stream")
		req = withUserContext(req, bob, wrapKey)
		w := httptest.NewRecorder()

		handler.Import(w, req)
		require.Equal(t, http.StatusOK, w.Code)
	})

	// Alice revoke share 200 
	t.Run("POST /api/shares/{id}/revoke - Alice revokes access", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/shares/"+shareID+"/revoke", nil)
		req.SetPathValue("id", shareID)
		req = withUserContext(req, alice, wrapKey)
		w := httptest.NewRecorder()

		handler.Revoke(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var res map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &res)
		require.NoError(t, err)
		assert.Equal(t, "revoked", res["status"])
	})

	// Inbox and Outgoing list endpoints work
	t.Run("GET /api/shares/inbox and outgoing", func(t *testing.T) {
		inboxReq := httptest.NewRequest(http.MethodGet, "/api/shares/inbox", nil)
		inboxReq = withUserContext(inboxReq, alice, wrapKey)
		wInbox := httptest.NewRecorder()
		handler.ListInbox(wInbox, inboxReq)
		assert.Equal(t, http.StatusOK, wInbox.Code)

		outReq := httptest.NewRequest(http.MethodGet, "/api/shares/outgoing", nil)
		outReq = withUserContext(outReq, bob, wrapKey)
		wOut := httptest.NewRecorder()
		handler.ListOutgoing(wOut, outReq)
		assert.Equal(t, http.StatusOK, wOut.Code)
	})
}
