package files

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/crypto/production"
	"github.com/ilhmpbta/CypherSecurity/internal/keys"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
	"github.com/ilhmpbta/CypherSecurity/internal/sharing"
	"github.com/ilhmpbta/CypherSecurity/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestFilesAndSharing(t *testing.T) (*Service, *sharing.Service, *storage.FS, *fakeFileRepo, *keys.Fake, *production.KeyManager) {
	tmpDir := t.TempDir()
	fs, err := storage.NewFS(tmpDir)
	require.NoError(t, err)

	kek := bytes.Repeat([]byte{0x42}, 32)
	km, err := production.New(map[int][]byte{1: kek})
	require.NoError(t, err)

	fileRepo := newFakeFileRepo()
	keysFake := keys.NewFake()
	shareRepo := sharing.NewFakeShareRepo(fileRepo, nil, nil)

	sharingSvc := sharing.NewService(shareRepo, fileRepo, km, keysFake, nil)
	fileSvc := NewService(fileRepo, fs, km, nil, WithKeysService(keysFake), WithSharingService(sharingSvc))

	return fileSvc, sharingSvc, fs, fileRepo, keysFake, km
}

func TestFiles_OpenShared_Flow(t *testing.T) {
	ctx := context.Background()
	fileSvc, sharingSvc, _, _, keysFake, _ := setupTestFilesAndSharing(t)

	ownerID := uuid.New()
	requesterID := uuid.New()
	ownerSess := keys.Session{UserID: ownerID, WrapKey: []byte("01234567890123456789012345678901")}
	reqSess := keys.Session{UserID: requesterID, WrapKey: []byte("01234567890123456789012345678901")}

	_, err := keysFake.EnsureForUser(ctx, ownerSess)
	require.NoError(t, err)
	_, err = keysFake.EnsureForUser(ctx, reqSess)
	require.NoError(t, err)

	// Owner uploads a valid PDF file
	originalContent := []byte("%PDF-1.4\nHighly confidential report data bytes 12345\n%%EOF")
	file, err := fileSvc.Upload(ctx, ownerID, bytes.NewReader(originalContent), "application/pdf", "report.pdf")
	require.NoError(t, err)

	// Before requesting or approving, OpenShared returns ErrForbidden
	_, _, err = fileSvc.OpenShared(ctx, file.ID, reqSess)
	assert.ErrorIs(t, err, ErrForbidden)

	// Bob requests access
	req, _, err := sharingSvc.Request(ctx, requesterID, file.ID, "Need report")
	require.NoError(t, err)

	// Still forbidden
	_, _, err = fileSvc.OpenShared(ctx, file.ID, reqSess)
	assert.ErrorIs(t, err, ErrForbidden)

	// Alice approves
	_, err = sharingSvc.Approve(ctx, req.ID, ownerSess)
	require.NoError(t, err)

	// Still forbidden
	_, _, err = fileSvc.OpenShared(ctx, file.ID, reqSess)
	assert.ErrorIs(t, err, ErrForbidden)

	// Alice exports, Bob imports
	blob, _, err := sharingSvc.Export(ctx, req.ID, ownerSess)
	require.NoError(t, err)
	_, err = sharingSvc.Import(ctx, requesterID, blob)
	require.NoError(t, err)

	// Bob can open shared file
	rc, meta, err := fileSvc.OpenShared(ctx, file.ID, reqSess)
	require.NoError(t, err)
	assert.Equal(t, file.ID, meta.ID)
	assert.Equal(t, "report.pdf", meta.OriginalName)

	downloaded, err := io.ReadAll(rc)
	_ = rc.Close()
	require.NoError(t, err)
	assert.Equal(t, originalContent, downloaded)

	// Locked session returns keys.ErrSessionLocked
	lockedSess := keys.Session{UserID: requesterID, WrapKey: nil}
	_, _, err = fileSvc.OpenShared(ctx, file.ID, lockedSess)
	assert.ErrorIs(t, err, keys.ErrSessionLocked)

	// Alice revokes share
	_, err = sharingSvc.Revoke(ctx, req.ID, ownerID)
	require.NoError(t, err)

	// Bob can no longer open shared
	_, _, err = fileSvc.OpenShared(ctx, file.ID, reqSess)
	assert.ErrorIs(t, err, ErrForbidden)

	// Not Exist file returns ErrNotFound
	_, _, err = fileSvc.OpenShared(ctx, uuid.New(), reqSess)
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestFiles_List_Extended(t *testing.T) {
	ctx := context.Background()
	fileSvc, sharingSvc, _, _, keysFake, _ := setupTestFilesAndSharing(t)

	aliceID := uuid.New()
	bobID := uuid.New()
	aliceSess := keys.Session{UserID: aliceID, WrapKey: []byte("01234567890123456789012345678901")}
	bobSess := keys.Session{UserID: bobID, WrapKey: []byte("01234567890123456789012345678901")}

	_, err := keysFake.EnsureForUser(ctx, aliceSess)
	require.NoError(t, err)
	_, err = keysFake.EnsureForUser(ctx, bobSess)
	require.NoError(t, err)

	// Alice uploads file1
	f1, err := fileSvc.Upload(ctx, aliceID, bytes.NewReader([]byte("%PDF-1.4 file1")), "application/pdf", "file1.pdf")
	require.NoError(t, err)

	// Bob uploads file2
	f2, err := fileSvc.Upload(ctx, bobID, bytes.NewReader([]byte("%PDF-1.4 file2")), "application/pdf", "file2.pdf")
	require.NoError(t, err)

	// Check Alice list view
	aliceList, err := fileSvc.List(ctx, aliceID)
	require.NoError(t, err)
	assert.Len(t, aliceList, 2)

	findFile := func(list []ListedFile, id uuid.UUID) *ListedFile {
		for _, f := range list {
			if f.ID == id {
				return &f
			}
		}
		return nil
	}

	aF1 := findFile(aliceList, f1.ID)
	require.NotNil(t, aF1)
	assert.Equal(t, "owner", aF1.Access)
	assert.Equal(t, 0, aF1.PendingRequestsCount)
	assert.Nil(t, aF1.MyPendingRequestID)
	assert.Equal(t, "none", aF1.ShareState)

	aF2 := findFile(aliceList, f2.ID)
	require.NotNil(t, aF2)
	assert.Equal(t, "shared", aF2.Access)
	assert.Equal(t, 0, aF2.PendingRequestsCount)
	assert.Nil(t, aF2.MyPendingRequestID)
	assert.Equal(t, "none", aF2.ShareState)

	// Bob request access to file1
	req, _, err := sharingSvc.Request(ctx, bobID, f1.ID, "Requesting file1")
	require.NoError(t, err)

	// Alice check list view again
	aliceList, err = fileSvc.List(ctx, aliceID)
	require.NoError(t, err)
	aF1 = findFile(aliceList, f1.ID)
	assert.Equal(t, 1, aF1.PendingRequestsCount)

	// Bob checks list view
	bobList, err := fileSvc.List(ctx, bobID)
	require.NoError(t, err)
	bF1 := findFile(bobList, f1.ID)
	assert.Equal(t, "shared", bF1.Access)
	require.NotNil(t, bF1.MyPendingRequestID)
	assert.Equal(t, req.ID, *bF1.MyPendingRequestID)
	assert.Equal(t, "pending", bF1.ShareState)
}
