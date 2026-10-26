package files

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/crypto/production"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
	"github.com/ilhmpbta/CypherSecurity/internal/storage"
)

type fakeFileRepo struct {
	mu    sync.Mutex
	files map[uuid.UUID]repository.File
}

func newFakeFileRepo() *fakeFileRepo {
	return &fakeFileRepo{files: make(map[uuid.UUID]repository.File)}
}

func (f *fakeFileRepo) Create(ctx context.Context, file repository.File) (repository.File, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[file.ID] = file
	return file, nil
}

func (f *fakeFileRepo) GetByIDForOwner(ctx context.Context, id, ownerID uuid.UUID) (repository.File, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	file, ok := f.files[id]
	if !ok || file.OwnerID != ownerID {
		return repository.File{}, repository.ErrNotFound
	}
	return file, nil
}

func (f *fakeFileRepo) ListByOwner(ctx context.Context, ownerID uuid.UUID) ([]repository.File, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var list []repository.File
	for _, file := range f.files {
		if file.OwnerID == ownerID {
			list = append(list, file)
		}
	}
	return list, nil
}

func (f *fakeFileRepo) DeleteByOwner(ctx context.Context, id, ownerID uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	file, ok := f.files[id]
	if !ok || file.OwnerID != ownerID {
		return repository.ErrNotFound
	}
	delete(f.files, id)
	return nil
}

func setupTestService(t *testing.T) (*Service, *storage.FS, string) {
	tmpDir := t.TempDir()
	fs, err := storage.NewFS(tmpDir)
	if err != nil {
		t.Fatalf("NewFS: %v", err)
	}
	kek := bytes.Repeat([]byte{0x42}, 32)
	km, err := production.New(map[int][]byte{1: kek})
	if err != nil {
		t.Fatalf("production.New KeyManager: %v", err)
	}
	repo := newFakeFileRepo()
	svc := NewService(repo, fs, km)
	return svc, fs, tmpDir
}

func TestServiceRoundTrip1MB(t *testing.T) {
	svc, _, _ := setupTestService(t)
	ownerID := uuid.New()

	content := make([]byte, 1024*1024)
	copy(content, "%PDF-1.4 test data")
	rng := rand.New(rand.NewSource(42))
	_, _ = rng.Read(content[15:])

	hashOriginal := sha256.Sum256(content)

	file, err := svc.Upload(context.Background(), ownerID, bytes.NewReader(content), "application/pdf", "test.pdf")
	if err != nil {
		t.Fatalf("Upload failed: %v", err)
	}

	if file.OriginalName != "test.pdf" {
		t.Errorf("expected original name 'test.pdf', got %q", file.OriginalName)
	}

	reader, meta, err := svc.Download(context.Background(), file.ID, ownerID)
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}
	defer func() {
		_ = reader.Close()
	}()

	if meta.ID != file.ID {
		t.Errorf("meta ID mismatch")
	}

	downloaded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	hashDownloaded := sha256.Sum256(downloaded)
	if hashOriginal != hashDownloaded {
		t.Errorf("SHA-256 mismatch between original and downloaded")
	}
}

type hundredMBReader struct {
	total   int64
	written int64
	header  []byte
	rng     *rand.Rand
}

func (hr *hundredMBReader) Read(p []byte) (int, error) {
	if hr.written >= hr.total {
		return 0, io.EOF
	}

	remaining := hr.total - hr.written
	n := int64(len(p))
	if n > remaining {
		n = remaining
	}

	buf := p[:n]
	var readN int
	if hr.written == 0 {
		copyBytes := int64(len(hr.header))
		if copyBytes > n {
			copyBytes = n
		}
		copy(buf, hr.header[:copyBytes])
		readN = int(copyBytes)
		hr.written += copyBytes
	} else {
		rn, _ := hr.rng.Read(buf)
		readN = rn
		hr.written += int64(rn)
	}
	return readN, nil
}

func TestServiceRoundTrip100MB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 100MB round-trip test in short mode")
	}

	svc, _, _ := setupTestService(t)
	ownerID := uuid.New()

	const size = 100 * 1024 * 1024
	pdfHeader := []byte("%PDF-1.4 100MB video/document test\n")

	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	r := &hundredMBReader{total: size, header: pdfHeader, rng: rand.New(rand.NewSource(1337))}
	file, err := svc.Upload(context.Background(), ownerID, r, "application/pdf", "large.pdf")
	if err != nil {
		t.Fatalf("100MB Upload failed: %v", err)
	}

	runtime.GC()
	runtime.ReadMemStats(&m2)
	rssGrowth := int64(m2.Sys) - int64(m1.Sys)
	t.Logf("100MB Upload RSS growth: %d bytes", rssGrowth)
	if rssGrowth > 80*1024*1024 {
		t.Errorf("RSS growth too high for streaming: %d bytes (expected < 80MB)", rssGrowth)
	}

	reader, _, err := svc.Download(context.Background(), file.ID, ownerID)
	if err != nil {
		t.Fatalf("100MB Download failed: %v", err)
	}
	defer func() {
		_ = reader.Close()
	}()

	buf := make([]byte, 32*1024)
	var downloadedSize int64
	for {
		n, err := reader.Read(buf)
		downloadedSize += int64(n)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("Read error during download: %v", err)
		}
	}

	if downloadedSize != size {
		t.Errorf("expected downloaded size %d, got %d", size, downloadedSize)
	}
}

type failingReader struct {
	data   []byte
	offset int
	failAt int
}

func (fr *failingReader) Read(p []byte) (int, error) {
	if fr.offset >= fr.failAt || fr.offset >= len(fr.data) {
		return 0, errors.New("interrupted stream")
	}
	n := copy(p, fr.data[fr.offset:min(len(fr.data), fr.failAt)])
	fr.offset += n
	return n, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestServiceInterruptedUpload(t *testing.T) {
	svc, _, root := setupTestService(t)
	ownerID := uuid.New()

	data := []byte("%PDF-1.4 data that will fail halfway through processing")
	fr := &failingReader{data: data, failAt: 10}

	_, err := svc.Upload(context.Background(), ownerID, fr, "application/pdf", "interrupted.pdf")
	if err == nil {
		t.Fatal("expected error from interrupted upload, got nil")
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) > 0 {
		t.Errorf("expected 0 files in storage root after failed upload, found %d", len(entries))
	}

	files, err := svc.List(context.Background(), ownerID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(files) > 0 {
		t.Errorf("expected 0 files in repository, found %d", len(files))
	}
}

func TestServiceCrossUserAccess(t *testing.T) {
	svc, _, _ := setupTestService(t)
	userA := uuid.New()
	userB := uuid.New()

	file, err := svc.Upload(context.Background(), userA, bytes.NewReader([]byte("%PDF-1.4 secret")), "application/pdf", "secret.pdf")
	if err != nil {
		t.Fatalf("Upload failed: %v", err)
	}

	_, _, err = svc.Download(context.Background(), file.ID, userB)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("expected ErrNotFound for cross-user download, got %v", err)
	}

	err = svc.Delete(context.Background(), file.ID, userB)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("expected ErrNotFound for cross-user delete, got %v", err)
	}
}

func TestServicePathTraversalFilename(t *testing.T) {
	svc, _, _ := setupTestService(t)
	ownerID := uuid.New()

	maliciousName := "../../../etc/passwd"
	file, err := svc.Upload(context.Background(), ownerID, bytes.NewReader([]byte("%PDF-1.4 safe content")), "application/pdf", maliciousName)
	if err != nil {
		t.Fatalf("Upload failed: %v", err)
	}

	if file.OriginalName != maliciousName {
		t.Errorf("expected OriginalName %q, got %q", maliciousName, file.OriginalName)
	}

	if len(file.StorageKey) != 32 {
		t.Errorf("expected 32 hex chars storage key, got len %d", len(file.StorageKey))
	}

	if _, err := os.Stat("../../../etc/passwd"); err == nil {
		t.Errorf("security violation: file written outside root")
	}
}

func TestServiceContentTypeMismatch(t *testing.T) {
	svc, _, _ := setupTestService(t)
	ownerID := uuid.New()

	jpegBytes := []byte("\xff\xd8\xff\xe0 jpeg data...")
	_, err := svc.Upload(context.Background(), ownerID, bytes.NewReader(jpegBytes), "application/pdf", "fake.pdf")
	if err == nil {
		t.Errorf("expected error for content type mismatch, got nil")
	}
}

func TestServiceCorruptedCiphertext(t *testing.T) {
	svc, _, root := setupTestService(t)
	ownerID := uuid.New()

	file, err := svc.Upload(context.Background(), ownerID, bytes.NewReader([]byte("%PDF-1.4 test data")), "application/pdf", "test.pdf")
	if err != nil {
		t.Fatalf("Upload failed: %v", err)
	}

	blobPath := filepath.Join(root, file.StorageKey)
	blobData, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("ReadFile blob: %v", err)
	}

	if len(blobData) > 20 {
		blobData[20] ^= 0xFF
	}
	if err := os.WriteFile(blobPath, blobData, 0600); err != nil {
		t.Fatalf("WriteFile corrupted blob: %v", err)
	}

	reader, _, err := svc.Download(context.Background(), file.ID, ownerID)
	if err == nil {
		defer func() {
			_ = reader.Close()
		}()
		_, err = io.ReadAll(reader)
	}
	if err == nil {
		t.Errorf("expected error reading corrupted ciphertext, got nil")
	}
}

func TestServiceDownloadTruncatedBlob(t *testing.T) {
	svc, _, root := setupTestService(t)
	ownerID := uuid.New()

	// Upload multi-chunk file or larger file to test truncation behavior
	content := make([]byte, 2*1024*1024) // 2 MiB (> 1 MiB chunk size)
	copy(content, "%PDF-1.4 large file truncation test")
	rng := rand.New(rand.NewSource(99))
	_, _ = rng.Read(content[35:])

	file, err := svc.Upload(context.Background(), ownerID, bytes.NewReader(content), "application/pdf", "large.pdf")
	if err != nil {
		t.Fatalf("Upload failed: %v", err)
	}

	// Truncate blob on disk (e.g. cut off after first chunk or middle)
	blobPath := filepath.Join(root, file.StorageKey)
	blobData, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("ReadFile blob: %v", err)
	}

	// Truncate to half size (mid-chunk or truncated stream)
	truncated := blobData[:len(blobData)/2]
	if err := os.WriteFile(blobPath, truncated, 0600); err != nil {
		t.Fatalf("WriteFile truncated blob: %v", err)
	}

	reader, _, err := svc.Download(context.Background(), file.ID, ownerID)
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}
	defer func() {
		_ = reader.Close()
	}()

	_, err = io.ReadAll(reader)
	if err == nil {
		t.Errorf("expected error reading truncated blob, got nil")
	}
}

func TestServiceRoundTripEmptyFile(t *testing.T) {
	svc, _, _ := setupTestService(t)
	ownerID := uuid.New()

	file, err := svc.Upload(context.Background(), ownerID, bytes.NewReader(nil), "application/pdf", "empty.pdf")
	if err != nil {
		t.Fatalf("Upload empty file failed: %v", err)
	}

	if file.PlaintextSize != 0 {
		t.Errorf("expected plaintextSize 0, got %d", file.PlaintextSize)
	}

	reader, _, err := svc.Download(context.Background(), file.ID, ownerID)
	if err != nil {
		t.Fatalf("Download empty file failed: %v", err)
	}
	defer func() {
		_ = reader.Close()
	}()

	downloaded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll empty file failed: %v", err)
	}

	if len(downloaded) != 0 {
		t.Errorf("expected 0 bytes downloaded, got %d", len(downloaded))
	}
}
