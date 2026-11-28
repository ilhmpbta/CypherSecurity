package sharing

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/crypto/production"
	"github.com/ilhmpbta/CypherSecurity/internal/keys"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockFileRepo struct {
	files map[uuid.UUID]repository.File
}

func newMockFileRepo() *mockFileRepo {
	return &mockFileRepo{files: make(map[uuid.UUID]repository.File)}
}

func (m *mockFileRepo) Create(ctx context.Context, f repository.File) (repository.File, error) {
	m.files[f.ID] = f
	return f, nil
}

func (m *mockFileRepo) GetByIDForOwner(ctx context.Context, id, ownerID uuid.UUID) (repository.File, error) {
	f, ok := m.files[id]
	if !ok || f.OwnerID != ownerID {
		return repository.File{}, repository.ErrNotFound
	}
	return f, nil
}

func (m *mockFileRepo) GetByID(ctx context.Context, id uuid.UUID) (repository.File, error) {
	f, ok := m.files[id]
	if !ok {
		return repository.File{}, repository.ErrNotFound
	}
	return f, nil
}

func (m *mockFileRepo) ListByOwner(ctx context.Context, ownerID uuid.UUID) ([]repository.File, error) {
	var out []repository.File
	for _, f := range m.files {
		if f.OwnerID == ownerID {
			out = append(out, f)
		}
	}
	return out, nil
}

func (m *mockFileRepo) ListAll(ctx context.Context) ([]repository.File, error) {
	var out []repository.File
	for _, f := range m.files {
		out = append(out, f)
	}
	return out, nil
}

func (m *mockFileRepo) DeleteByOwner(ctx context.Context, id, ownerID uuid.UUID) error {
	f, ok := m.files[id]
	if !ok || f.OwnerID != ownerID {
		return repository.ErrNotFound
	}
	delete(m.files, id)
	return nil
}

func (m *mockFileRepo) UpdateForOwner(ctx context.Context, f repository.File) (repository.File, error) {
	existing, ok := m.files[f.ID]
	if !ok || existing.OwnerID != f.OwnerID {
		return repository.File{}, repository.ErrNotFound
	}
	m.files[f.ID] = f
	return f, nil
}

type mockUserRepo struct {
	users map[uuid.UUID]repository.User
}

func (m *mockUserRepo) Create(ctx context.Context, username, passwordHash string) (repository.User, error) {
	u := repository.User{ID: uuid.New(), Username: username, PasswordHash: passwordHash}
	m.users[u.ID] = u
	return u, nil
}

func (m *mockUserRepo) GetByUsername(ctx context.Context, username string) (repository.User, error) {
	for _, u := range m.users {
		if u.Username == username {
			return u, nil
		}
	}
	return repository.User{}, repository.ErrNotFound
}

func (m *mockUserRepo) GetByID(ctx context.Context, id uuid.UUID) (repository.User, error) {
	u, ok := m.users[id]
	if !ok {
		return repository.User{}, repository.ErrNotFound
	}
	return u, nil
}

func setupTestSharingService(t *testing.T) (*Service, *FakeShareRepo, *mockFileRepo, *keys.Fake, *production.KeyManager) {
	kek := bytes.Repeat([]byte{0x42}, 32)
	km, err := production.New(map[int][]byte{1: kek})
	require.NoError(t, err)

	fileRepo := newMockFileRepo()
	userRepo := &mockUserRepo{users: make(map[uuid.UUID]repository.User)}
	keysFake := keys.NewFake()

	shareRepo := NewFakeShareRepo(fileRepo, userRepo, nil)
	svc := NewService(shareRepo, fileRepo, km, keysFake, nil)

	return svc, shareRepo, fileRepo, keysFake, km
}

func TestSharingLifecycle_FullFlow(t *testing.T) {
	ctx := context.Background()
	svc, _, fileRepo, keysFake, km := setupTestSharingService(t)

	ownerID := uuid.New()
	requesterID := uuid.New()
	ownerSess := keys.Session{UserID: ownerID, WrapKey: []byte("01234567890123456789012345678901")}
	reqSess := keys.Session{UserID: requesterID, WrapKey: []byte("01234567890123456789012345678901")}

	_, err := keysFake.EnsureForUser(ctx, ownerSess)
	require.NoError(t, err)
	_, err = keysFake.EnsureForUser(ctx, reqSess)
	require.NoError(t, err)

	// Create a stored file owned by Alice
	rawDEK, err := km.GenerateDEK()
	require.NoError(t, err)
	wrappedDEK, _, err := km.Wrap(rawDEK)
	require.NoError(t, err)

	file := repository.File{
		ID:            uuid.New(),
		OwnerID:       ownerID,
		OriginalName:  "financial_report.pdf",
		ContentType:   "application/pdf",
		PlaintextSize: 1024,
		WrappedDEK:    wrappedDEK,
	}
	_, err = fileRepo.Create(ctx, file)
	require.NoError(t, err)

	// Bob request access to Alice's file
	req, created, err := svc.Request(ctx, requesterID, file.ID, "Need access for review")
	require.NoError(t, err)
	assert.True(t, created)
	assert.Equal(t, StatusPending, req.Status)
	assert.Equal(t, "financial_report.pdf", req.FileName)

	// Duplicate request return 200 
	dupReq, created, err := svc.Request(ctx, requesterID, file.ID, "Duplicate request")
	require.NoError(t, err)
	assert.False(t, created)
	assert.Equal(t, req.ID, dupReq.ID)

	// Bob cannot access before approval
	active, err := svc.GetActiveShare(ctx, requesterID, file.ID)
	assert.ErrorIs(t, err, ErrNoActiveShare)
	assert.Nil(t, active)

	// Non-owner cannot approve
	_, err = svc.Approve(ctx, req.ID, reqSess)
	assert.ErrorIs(t, err, ErrForbidden)

	// Locked session cannot approve
	lockedSess := keys.Session{UserID: ownerID, WrapKey: nil}
	_, err = svc.Approve(ctx, req.ID, lockedSess)
	assert.ErrorIs(t, err, keys.ErrSessionLocked)

	// Alice approves request
	approvedReq, err := svc.Approve(ctx, req.ID, ownerSess)
	require.NoError(t, err)
	assert.Equal(t, StatusApproved, approvedReq.Status)
	assert.NotNil(t, approvedReq.DecidedAt)

	// Non-owner cannot export
	_, _, err = svc.Export(ctx, req.ID, reqSess)
	assert.ErrorIs(t, err, ErrForbidden)

	// Alice export .cskey
	blob, filename, err := svc.Export(ctx, req.ID, ownerSess)
	require.NoError(t, err)
	assert.NotEmpty(t, blob)
	assert.Equal(t, "financial_report.pdf", filename)

	// Tampered .cskey is rejected
	tampered := make([]byte, len(blob))
	copy(tampered, blob)
	tampered[len(tampered)-5] ^= 0xAA
	_, err = svc.Import(ctx, requesterID, tampered)
	assert.ErrorIs(t, err, ErrValidationFailed)

	// Non-requester cannot import
	_, err = svc.Import(ctx, ownerID, blob)
	assert.ErrorIs(t, err, ErrForbidden)

	// Bob import valid .cskey
	importedReq, err := svc.Import(ctx, requesterID, blob)
	require.NoError(t, err)
	assert.NotNil(t, importedReq.ImportedAt)

	// Re-import is idempotent
	reimportedReq, err := svc.Import(ctx, requesterID, blob)
	require.NoError(t, err)
	assert.Equal(t, importedReq.ID, reimportedReq.ID)

	// Active share is now accessible
	activeShare, err := svc.GetActiveShare(ctx, requesterID, file.ID)
	require.NoError(t, err)
	assert.NotNil(t, activeShare)
	assert.NotEmpty(t, activeShare.WrappedDEK)

	// Unwrap active share wrappedDEK using Bob session
	unwrappedDEK, err := keysFake.UnwrapForRequester(ctx, reqSess, activeShare.WrappedDEK)
	require.NoError(t, err)
	assert.Equal(t, rawDEK, unwrappedDEK)

	// Revoke close access
	_, err = svc.Revoke(ctx, req.ID, ownerSess.UserID)
	require.NoError(t, err)

	activeAfterRevoke, err := svc.GetActiveShare(ctx, requesterID, file.ID)
	assert.ErrorIs(t, err, ErrNoActiveShare)
	assert.Nil(t, activeAfterRevoke)

	// Cannot import after revoke
	_, err = svc.Import(ctx, requesterID, blob)
	assert.ErrorIs(t, err, ErrInvalidTransition)
}

func TestSharingRejectFlow(t *testing.T) {
	ctx := context.Background()
	svc, _, fileRepo, keysFake, km := setupTestSharingService(t)

	ownerID := uuid.New()
	requesterID := uuid.New()
	ownerSess := keys.Session{UserID: ownerID, WrapKey: []byte("01234567890123456789012345678901")}

	_, err := keysFake.EnsureForUser(ctx, ownerSess)
	require.NoError(t, err)

	rawDEK, err := km.GenerateDEK()
	require.NoError(t, err)
	wrappedDEK, _, err := km.Wrap(rawDEK)
	require.NoError(t, err)

	file := repository.File{
		ID:         uuid.New(),
		OwnerID:    ownerID,
		WrappedDEK: wrappedDEK,
	}
	_, err = fileRepo.Create(ctx, file)
	require.NoError(t, err)

	req, _, err := svc.Request(ctx, requesterID, file.ID, "Please share")
	require.NoError(t, err)

	// Non-owner cannot reject
	_, err = svc.Reject(ctx, req.ID, requesterID)
	assert.ErrorIs(t, err, ErrForbidden)

	// Owner reject
	rejectedReq, err := svc.Reject(ctx, req.ID, ownerID)
	require.NoError(t, err)
	assert.Equal(t, StatusRejected, rejectedReq.Status)
	assert.NotNil(t, rejectedReq.DecidedAt)

	// Cannot approve rejected request
	_, err = svc.Approve(ctx, req.ID, ownerSess)
	assert.ErrorIs(t, err, ErrInvalidTransition)

	// Access is closed
	active, err := svc.GetActiveShare(ctx, requesterID, file.ID)
	assert.ErrorIs(t, err, ErrNoActiveShare)
	assert.Nil(t, active)
}

func TestSharingEdgeCases(t *testing.T) {
	ctx := context.Background()
	svc, _, fileRepo, _, _ := setupTestSharingService(t)

	ownerID := uuid.New()
	requesterID := uuid.New()

	file := repository.File{
		ID:      uuid.New(),
		OwnerID: ownerID,
	}
	_, err := fileRepo.Create(ctx, file)
	require.NoError(t, err)

	t.Run("owner cannot request own file", func(t *testing.T) {
		_, _, err := svc.Request(ctx, ownerID, file.ID, "")
		assert.ErrorIs(t, err, ErrForbidden)
	})

	t.Run("request non-existent file", func(t *testing.T) {
		_, _, err := svc.Request(ctx, requesterID, uuid.New(), "")
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("import with non-existent request returns 404", func(t *testing.T) {
		fakeReq := ShareRequest{
			ID:     uuid.New(),
			FileID: file.ID,
			Owner: ShareIdentity{
				ID:          ownerID,
				Fingerprint: "0123456789012345678901234567890123456789012345678901234567890123",
			},
			Requester: ShareIdentity{
				ID:          requesterID,
				Fingerprint: "0123456789012345678901234567890123456789012345678901234567890123",
			},
		}
		dummyBlob, err := EncodeBlob(fakeReq, []byte("key"), func(d []byte) ([]byte, error) {
			return make([]byte, 256), nil
		})
		require.NoError(t, err)

		_, err = svc.Import(ctx, requesterID, dummyBlob)
		assert.ErrorIs(t, err, ErrNotFound)
	})
}
