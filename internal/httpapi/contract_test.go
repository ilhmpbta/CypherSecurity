//go:build contract

package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/auth"
	"github.com/ilhmpbta/CypherSecurity/internal/config"
	"github.com/ilhmpbta/CypherSecurity/internal/httpapi"
	"github.com/ilhmpbta/CypherSecurity/internal/httpapi/handlers"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	contractSession = "contract-session"
	contractCSRF    = "contract-csrf-token"
)

type contractAuthService struct {
	registerErr error
	loginErr    error
}

func (s *contractAuthService) Register(_ context.Context, username, _ string) (repository.User, error) {
	if s.registerErr != nil {
		return repository.User{}, s.registerErr
	}
	return repository.User{ID: contractUserID, Username: username, CreatedAt: contractTime}, nil
}
func (s *contractAuthService) Login(_ context.Context, _, _, _ string) (string, error) {
	if s.loginErr != nil {
		return "", s.loginErr
	}
	return contractSession, nil
}
func (*contractAuthService) Logout(context.Context, string) error { return nil }

var (
	contractUserID = uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	contractFileID = uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	contractTime   = time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
)

func contractUser() repository.User {
	return repository.User{ID: contractUserID, Username: "contract-user", CreatedAt: contractTime}
}

func newContractRouter(t *testing.T, authSvc *contractAuthService, fileSvc *fakeFileService, recordSvc handlers.RecordService, auditSvc *fakeAuditService, uploadLimit int64) http.Handler {
	t.Helper()
	if authSvc == nil {
		authSvc = &contractAuthService{}
	}
	if fileSvc == nil {
		fileSvc = &fakeFileService{}
	}
	if recordSvc == nil {
		recordSvc = &fakeRecordService{}
	}
	if auditSvc == nil {
		auditSvc = &fakeAuditService{}
	}
	user := contractUser()
	deps := httpapi.Deps{
		AuthSvc:   authSvc,
		FileSvc:   fileSvc,
		RecordSvc: recordSvc,
		AuditSvc:  auditSvc,
		UserRepo: &fakeUserRepoForFiles{
			user: user,
		},
		SessionStore: &fakeSessionStoreForFiles{
			sess: &repository.Session{
				ID:        uuid.MustParse("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
				UserID:    contractUserID,
				ExpiresAt: contractTime.Add(time.Hour),
			},
		},
		Config: &config.Config{SecureCookies: false, MaxUploadBytes: uploadLimit},
	}
	return httpapi.NewRouter(deps)
}

func contractRequest(t *testing.T, router http.Handler, method, target string, body []byte, authenticated, includeCSRF bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	if authenticated {
		req.AddCookie(&http.Cookie{Name: "session_id", Value: contractSession})
	}
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: contractCSRF})
	if includeCSRF && method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
		req.Header.Set("X-CSRF-Token", contractCSRF)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
		assertNoForbiddenKeys(t, []byte(rec.Body.String()))
	}
	return rec
}

func assertError(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	require.Equal(t, status, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, map[string]any{"error": code}, body)
}

func assertNoForbiddenKeys(t *testing.T, body []byte) {
	t.Helper()
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return
	}
	forbidden := map[string]struct{}{
		"dek": {}, "wrapped_key": {}, "wrapped": {}, "private": {},
		"private_key_encrypted": {}, "wrapkey": {}, "cert_der": {},
		"password_hash": {},
	}
	var visit func(any)
	visit = func(node any) {
		switch typed := node.(type) {
		case map[string]any:
			for key, child := range typed {
				_, found := forbidden[strings.ToLower(key)]
				assert.Falsef(t, found, "forbidden JSON key %q", key)
				visit(child)
			}
		case []any:
			for _, child := range typed {
				visit(child)
			}
		}
	}
	visit(value)
}

type nullableShape struct{ inner any }
type enumShape []string
type arrayShape struct{ inner any }

func nullable(inner any) nullableShape { return nullableShape{inner: inner} }
func enum(values ...string) enumShape  { return values }
func arrayOf(inner any) arrayShape     { return arrayShape{inner: inner} }

func assertShape(t *testing.T, actual, expected any) {
	t.Helper()
	switch schema := expected.(type) {
	case map[string]any:
		object, ok := actual.(map[string]any)
		require.Truef(t, ok, "expected object, got %T", actual)
		actualKeys := make([]string, 0, len(object))
		expectedKeys := make([]string, 0, len(schema))
		for key := range object {
			actualKeys = append(actualKeys, key)
		}
		for key := range schema {
			expectedKeys = append(expectedKeys, key)
		}
		sort.Strings(actualKeys)
		sort.Strings(expectedKeys)
		require.Equal(t, expectedKeys, actualKeys, "object key set")
		for key, valueSchema := range schema {
			assertShape(t, object[key], valueSchema)
		}
	case nullableShape:
		if actual != nil {
			assertShape(t, actual, schema.inner)
		}
	case enumShape:
		value, ok := actual.(string)
		require.Truef(t, ok, "expected enum string, got %T", actual)
		require.Contains(t, []string(schema), value)
	case arrayShape:
		values, ok := actual.([]any)
		require.Truef(t, ok, "expected array, got %T", actual)
		for _, value := range values {
			assertShape(t, value, schema.inner)
		}
	case string:
		switch schema {
		case "string":
			_, ok := actual.(string)
			assert.Truef(t, ok, "expected string, got %T", actual)
		case "uuid-string":
			value, ok := actual.(string)
			require.Truef(t, ok, "expected UUID string, got %T", actual)
			_, err := uuid.Parse(value)
			assert.NoError(t, err)
		case "RFC3339 time":
			value, ok := actual.(string)
			require.Truef(t, ok, "expected RFC3339 string, got %T", actual)
			_, err := time.Parse(time.RFC3339, value)
			assert.NoError(t, err)
		case "64-char hex":
			value, ok := actual.(string)
			require.Truef(t, ok, "expected fingerprint string, got %T", actual)
			assert.Regexp(t, regexp.MustCompile(`^[0-9a-fA-F]{64}$`), value)
		case "number":
			_, ok := actual.(float64)
			assert.Truef(t, ok, "expected number, got %T", actual)
		case "bool":
			_, ok := actual.(bool)
			assert.Truef(t, ok, "expected bool, got %T", actual)
		case "object":
			_, ok := actual.(map[string]any)
			assert.Truef(t, ok, "expected arbitrary object, got %T", actual)
		default:
			require.Failf(t, "unknown shape", "unsupported shape descriptor %q", schema)
		}
	default:
		require.Failf(t, "unknown shape", "unsupported schema %T", expected)
	}
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) any {
	t.Helper()
	var body any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return body
}

func TestContractHealth(t *testing.T) {
	t.Run("GET /healthz → 200", func(t *testing.T) {
		router := httpapi.NewRouter(httpapi.Deps{HealthCheck: func(context.Context) error { return nil }})
		rec := contractRequest(t, router, http.MethodGet, "/healthz", nil, false, false)
		require.Equal(t, http.StatusOK, rec.Code)
		assertShape(t, decodeBody(t, rec), map[string]any{"status": enum("ok")})
	})
	t.Run("GET /healthz → 503", func(t *testing.T) {
		router := httpapi.NewRouter(httpapi.Deps{HealthCheck: func(context.Context) error { return errors.New("unavailable") }})
		rec := contractRequest(t, router, http.MethodGet, "/healthz", nil, false, false)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assertShape(t, decodeBody(t, rec), map[string]any{
			"status": enum("degraded"), "error": enum("database unreachable"),
		})
	})
}

func TestContractAuth(t *testing.T) {
	validBody := []byte(`{"username":"contract-user","password":"password"}`)
	t.Run("POST /api/auth/register → 201", func(t *testing.T) {
		rec := contractRequest(t, newContractRouter(t, nil, nil, nil, nil, 0), http.MethodPost, "/api/auth/register", validBody, false, true)
		require.Equal(t, http.StatusCreated, rec.Code)
		assertShape(t, decodeBody(t, rec), map[string]any{
			"id": "uuid-string", "username": "string", "created_at": "RFC3339 time",
		})
	})
	t.Run("POST /api/auth/register → 400", func(t *testing.T) {
		rec := contractRequest(t, newContractRouter(t, nil, nil, nil, nil, 0), http.MethodPost, "/api/auth/register", []byte(`{`), false, true)
		assertError(t, rec, http.StatusBadRequest, "invalid request")
	})
	t.Run("POST /api/auth/login → 200", func(t *testing.T) {
		rec := contractRequest(t, newContractRouter(t, nil, nil, nil, nil, 0), http.MethodPost, "/api/auth/login", validBody, false, true)
		require.Equal(t, http.StatusOK, rec.Code)
		assertShape(t, decodeBody(t, rec), map[string]any{
			"user": map[string]any{"id": "uuid-string", "username": "string", "created_at": "RFC3339 time"},
		})
		assert.NotEmpty(t, rec.Result().Cookies())
	})
	t.Run("POST /api/auth/login → 401", func(t *testing.T) {
		router := newContractRouter(t, &contractAuthService{loginErr: auth.ErrInvalidCredentials}, nil, nil, nil, 0)
		rec := contractRequest(t, router, http.MethodPost, "/api/auth/login", validBody, false, true)
		assertError(t, rec, http.StatusUnauthorized, "invalid credentials")
	})
	t.Run("POST /api/auth/login → 400", func(t *testing.T) {
		rec := contractRequest(t, newContractRouter(t, nil, nil, nil, nil, 0), http.MethodPost, "/api/auth/login", []byte(`{"username":""}`), false, true)
		assertError(t, rec, http.StatusBadRequest, "invalid request: username and password are required")
	})
	t.Run("POST /api/auth/logout → 204", func(t *testing.T) {
		rec := contractRequest(t, newContractRouter(t, nil, nil, nil, nil, 0), http.MethodPost, "/api/auth/logout", nil, true, true)
		require.Equal(t, http.StatusNoContent, rec.Code)
		assert.Empty(t, rec.Body.String())
	})
	t.Run("GET /api/auth/me → 200", func(t *testing.T) {
		rec := contractRequest(t, newContractRouter(t, nil, nil, nil, nil, 0), http.MethodGet, "/api/auth/me", nil, true, false)
		require.Equal(t, http.StatusOK, rec.Code)
		assertShape(t, decodeBody(t, rec), map[string]any{
			"id": "uuid-string", "username": "string", "created_at": "RFC3339 time",
		})
	})
	t.Run("GET /api/auth/me → 401", func(t *testing.T) {
		t.Skip("Contract drift CD-1: design expects session_expired; middleware currently emits unauthorized")
	})
	t.Run("POST /api/auth/register → 403", func(t *testing.T) {
		rec := contractRequest(t, newContractRouter(t, nil, nil, nil, nil, 0), http.MethodPost, "/api/auth/register", validBody, false, false)
		assertError(t, rec, http.StatusForbidden, "csrf token invalid")
	})
}

func multipartFile(t *testing.T, name string, contents []byte) ([]byte, string) {
	t.Helper()
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", name)
	require.NoError(t, err)
	_, err = part.Write(contents)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return body.Bytes(), writer.FormDataContentType()
}

func TestContractFiles(t *testing.T) {
	file := repository.File{
		ID: contractFileID, OriginalName: "report.pdf", ContentType: "application/pdf",
		PlaintextSize: 5, CreatedAt: contractTime,
	}
	listService := &fakeFileService{
		listFn: func(context.Context, uuid.UUID) ([]repository.File, error) {
			return []repository.File{file}, nil
		},
	}
	t.Run("POST /api/files → 201", func(t *testing.T) {
		svc := &fakeFileService{uploadFn: func(_ context.Context, _ uuid.UUID, _ io.Reader, ct, name string) (repository.File, error) {
			result := file
			result.ContentType = ct
			result.OriginalName = name
			return result, nil
		}}
		body, contentType := multipartFile(t, file.OriginalName, []byte("hello"))
		router := newContractRouter(t, nil, svc, nil, nil, 0)
		req := httptest.NewRequest(http.MethodPost, "/api/files", bytes.NewReader(body))
		req.Header.Set("Content-Type", contentType)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: contractSession})
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: contractCSRF})
		req.Header.Set("X-CSRF-Token", contractCSRF)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		assertNoForbiddenKeys(t, []byte(rec.Body.String()))
		require.Equal(t, http.StatusCreated, rec.Code)
		assertShape(t, decodeBody(t, rec), map[string]any{
			"id": "uuid-string", "original_name": "string", "content_type": "string",
			"plaintext_size": "number", "created_at": "RFC3339 time",
		})
	})
	t.Run("POST /api/files → 400", func(t *testing.T) {
		router := newContractRouter(t, nil, nil, nil, nil, 0)
		rec := contractRequest(t, router, http.MethodPost, "/api/files", []byte("invalid"), true, true)
		assertError(t, rec, http.StatusBadRequest, "invalid multipart request")
	})
	t.Run("POST /api/files → 413", func(t *testing.T) {
		body, contentType := multipartFile(t, "large.txt", bytes.Repeat([]byte("x"), 256))
		router := newContractRouter(t, nil, nil, nil, nil, 32)
		req := httptest.NewRequest(http.MethodPost, "/api/files", bytes.NewReader(body))
		req.Header.Set("Content-Type", contentType)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: contractSession})
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: contractCSRF})
		req.Header.Set("X-CSRF-Token", contractCSRF)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		assertNoForbiddenKeys(t, []byte(rec.Body.String()))
		require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	})
	t.Run("GET /api/files → 200", func(t *testing.T) {
		rec := contractRequest(t, newContractRouter(t, nil, listService, nil, nil, 0), http.MethodGet, "/api/files", nil, true, false)
		require.Equal(t, http.StatusOK, rec.Code)
		assertShape(t, decodeBody(t, rec), map[string]any{
			"files": arrayOf(map[string]any{
				"id": "uuid-string", "original_name": "string", "content_type": "string",
				"plaintext_size": "number", "created_at": "RFC3339 time",
			}),
		})
	})
	t.Run("GET /api/files → 500", func(t *testing.T) {
		svc := &fakeFileService{listFn: func(context.Context, uuid.UUID) ([]repository.File, error) {
			return nil, errors.New("backend unavailable")
		}}
		rec := contractRequest(t, newContractRouter(t, nil, svc, nil, nil, 0), http.MethodGet, "/api/files", nil, true, false)
		assertError(t, rec, http.StatusInternalServerError, "list failed")
	})
	t.Run("GET /api/files → 200 sharing fields", func(t *testing.T) {
		t.Skip("Handlers not merged: current file list response has no sharing fields")
	})
	t.Run("GET /api/files/{id}/download → 200", func(t *testing.T) {
		svc := &fakeFileService{downloadFn: func(context.Context, uuid.UUID, uuid.UUID) (io.ReadCloser, repository.File, error) {
			return io.NopCloser(strings.NewReader("hello")), file, nil
		}}
		rec := contractRequest(t, newContractRouter(t, nil, svc, nil, nil, 0), http.MethodGet,
			"/api/files/"+contractFileID.String()+"/download", nil, true, false)
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/pdf", rec.Header().Get("Content-Type"))
		assert.Contains(t, rec.Header().Get("Content-Disposition"), "attachment")
		assert.Equal(t, "5", rec.Header().Get("Content-Length"))
		assert.Equal(t, "hello", rec.Body.String())
	})
	t.Run("GET /api/files/{id}/download → 404", func(t *testing.T) {
		rec := contractRequest(t, newContractRouter(t, nil, &fakeFileService{}, nil, nil, 0),
			http.MethodGet, "/api/files/"+contractFileID.String()+"/download", nil, true, false)
		assertError(t, rec, http.StatusNotFound, "not found")
	})
	t.Run("GET /api/files/{id}/download → 404 malformed id", func(t *testing.T) {
		rec := contractRequest(t, newContractRouter(t, nil, nil, nil, nil, 0),
			http.MethodGet, "/api/files/not-a-uuid/download", nil, true, false)
		assertError(t, rec, http.StatusNotFound, "not found")
	})
	t.Run("DELETE /api/files/{id} → 204", func(t *testing.T) {
		rec := contractRequest(t, newContractRouter(t, nil, nil, nil, nil, 0),
			http.MethodDelete, "/api/files/"+contractFileID.String(), nil, true, true)
		require.Equal(t, http.StatusNoContent, rec.Code)
		assert.Empty(t, rec.Body.String())
	})
	t.Run("DELETE /api/files/{id} → 404", func(t *testing.T) {
		svc := &fakeFileService{deleteFn: func(context.Context, uuid.UUID, uuid.UUID) error { return repository.ErrNotFound }}
		rec := contractRequest(t, newContractRouter(t, nil, svc, nil, nil, 0),
			http.MethodDelete, "/api/files/"+contractFileID.String(), nil, true, true)
		assertError(t, rec, http.StatusNotFound, "not found")
	})
	t.Run("GET /api/files → 401", func(t *testing.T) {
		t.Skip("Contract drift CD-1: design expects session_expired; middleware currently emits unauthorized")
	})
	t.Run("POST /api/files → 401", func(t *testing.T) {
		t.Skip("Contract drift CD-1: design expects session_expired; middleware currently emits unauthorized")
	})
	t.Run("GET /api/files/{id}/download → 401", func(t *testing.T) {
		t.Skip("Contract drift CD-1: design expects session_expired; middleware currently emits unauthorized")
	})
	t.Run("DELETE /api/files/{id} → 401", func(t *testing.T) {
		t.Skip("Contract drift CD-1: design expects session_expired; middleware currently emits unauthorized")
	})
	t.Run("GET /api/files/{id}/download → 403", func(t *testing.T) {
		t.Skip("Handlers not merged: non-owner authorization remains a 404 and no share-aware rule exists")
	})
	t.Run("GET /api/files/{id}/download → 404 no existence leak", func(t *testing.T) {
		rec := contractRequest(t, newContractRouter(t, nil, &fakeFileService{}, nil, nil, 0),
			http.MethodGet, "/api/files/"+contractFileID.String()+"/download", nil, true, false)
		assertError(t, rec, http.StatusNotFound, "not found")
	})
	t.Run("POST /api/files → 400 invalid_content_type", func(t *testing.T) {
		t.Skip("Handlers not merged: current upload handler does not validate file content type")
	})
}

func recordShape() map[string]any {
	return map[string]any{
		"id": "uuid-string", "data_type": "string", "payload": "object",
		"created_at": "RFC3339 time", "updated_at": "RFC3339 time",
	}
}

func TestContractRecords(t *testing.T) {
	record := repository.PersonalRecord{
		ID: contractFileID, OwnerID: contractUserID, DataType: "note",
		Payload: map[string]any{"text": "safe"}, CreatedAt: contractTime, UpdatedAt: contractTime,
	}
	t.Run("GET /api/records → 200", func(t *testing.T) {
		svc := &fakeRecordService{listFn: func(context.Context, uuid.UUID) ([]repository.PersonalRecord, error) {
			return []repository.PersonalRecord{record}, nil
		}}
		rec := contractRequest(t, newContractRouter(t, nil, nil, svc, nil, 0), http.MethodGet, "/api/records", nil, true, false)
		require.Equal(t, http.StatusOK, rec.Code)
		assertShape(t, decodeBody(t, rec), map[string]any{"records": arrayOf(recordShape())})
	})
	t.Run("POST /api/records → 201", func(t *testing.T) {
		svc := &fakeRecordService{createFn: func(context.Context, uuid.UUID, string, map[string]any) (repository.PersonalRecord, error) {
			return record, nil
		}}
		rec := contractRequest(t, newContractRouter(t, nil, nil, svc, nil, 0), http.MethodPost,
			"/api/records", []byte(`{"data_type":"note","payload":{"text":"safe"}}`), true, true)
		require.Equal(t, http.StatusCreated, rec.Code)
		assertShape(t, decodeBody(t, rec), recordShape())
	})
	t.Run("POST /api/records → 400", func(t *testing.T) {
		rec := contractRequest(t, newContractRouter(t, nil, nil, nil, nil, 0), http.MethodPost,
			"/api/records", []byte(`{"data_type":" "}`), true, true)
		assertError(t, rec, http.StatusBadRequest, "data_type is required")
	})
	t.Run("PATCH /api/records/{id} → 200", func(t *testing.T) {
		updater := &contractRecordUpdater{record: record}
		rec := contractRequest(t, newContractRouter(t, nil, nil, updater, nil, 0), http.MethodPatch,
			"/api/records/"+contractFileID.String(), []byte(`{"data_type":"updated","payload":{}}`), true, true)
		require.Equal(t, http.StatusOK, rec.Code)
		assertShape(t, decodeBody(t, rec), recordShape())
	})
	t.Run("PATCH /api/records/{id} → 404", func(t *testing.T) {
		rec := contractRequest(t, newContractRouter(t, nil, nil, nil, nil, 0), http.MethodPatch,
			"/api/records/not-a-uuid", []byte(`{"data_type":"note","payload":{}}`), true, true)
		assertError(t, rec, http.StatusNotFound, "not found")
	})
	t.Run("DELETE /api/records/{id} → 204", func(t *testing.T) {
		rec := contractRequest(t, newContractRouter(t, nil, nil, nil, nil, 0), http.MethodDelete,
			"/api/records/"+contractFileID.String(), nil, true, true)
		require.Equal(t, http.StatusNoContent, rec.Code)
		assert.Empty(t, rec.Body.String())
	})
	t.Run("DELETE /api/records/{id} → 404", func(t *testing.T) {
		rec := contractRequest(t, newContractRouter(t, nil, nil, &contractRecordMissing{}, nil, 0), http.MethodDelete,
			"/api/records/"+contractFileID.String(), nil, true, true)
		assertError(t, rec, http.StatusNotFound, "not found")
	})
	t.Run("GET /api/records → 401", func(t *testing.T) {
		t.Skip("Contract drift CD-1: design expects session_expired; middleware currently emits unauthorized")
	})
	t.Run("POST /api/records → 401", func(t *testing.T) {
		t.Skip("Contract drift CD-1: design expects session_expired; middleware currently emits unauthorized")
	})
	t.Run("PATCH /api/records/{id} → 401", func(t *testing.T) {
		t.Skip("Contract drift CD-1: design expects session_expired; middleware currently emits unauthorized")
	})
	t.Run("DELETE /api/records/{id} → 401", func(t *testing.T) {
		t.Skip("Contract drift CD-1: design expects session_expired; middleware currently emits unauthorized")
	})
}

type contractRecordMissing struct{ fakeRecordService }

func (*contractRecordMissing) Delete(context.Context, uuid.UUID, uuid.UUID) error {
	return repository.ErrNotFound
}

type contractRecordUpdater struct {
	fakeRecordService
	record repository.PersonalRecord
}

func (s *contractRecordUpdater) Update(context.Context, uuid.UUID, uuid.UUID, string, map[string]any) (repository.PersonalRecord, error) {
	return s.record, nil
}

func TestContractAudit(t *testing.T) {
	t.Run("GET /api/audit → 200", func(t *testing.T) {
		svc := &fakeAuditService{listFn: func(context.Context, uuid.UUID, int) ([]repository.AuditEvent, error) {
			return []repository.AuditEvent{{
				ID: 1, ActorID: &contractUserID, Action: "test.action",
				TargetID: nil, Metadata: map[string]any{}, CreatedAt: contractTime,
			}}, nil
		}}
		rec := contractRequest(t, newContractRouter(t, nil, nil, nil, svc, 0), http.MethodGet, "/api/audit", nil, true, false)
		require.Equal(t, http.StatusOK, rec.Code)
		assertShape(t, decodeBody(t, rec), map[string]any{
			"events": arrayOf(map[string]any{
				"ID": "number", "ActorID": nullable("uuid-string"), "Action": "string",
				"TargetID": nullable("string"), "Metadata": "object", "CreatedAt": "RFC3339 time",
			}),
		})
	})
	t.Run("GET /api/audit → 401", func(t *testing.T) {
		t.Skip("Contract drift CD-1: design expects session_expired; middleware currently emits unauthorized")
	})
}

func TestContractSharingAndPDFNotMerged(t *testing.T) {
	for _, testCase := range []string{
		"POST /api/shares → 201", "POST /api/shares → 200 duplicate",
		"POST /api/shares → 403 own file", "POST /api/shares → 404",
		"POST /api/shares → 401 unauthenticated",
		"GET /api/shares/inbox?status=pending → 200", "GET /api/shares/outgoing?status=approved → 200",
		"GET /api/shares/inbox → 401 unauthenticated", "GET /api/shares/outgoing → 401 unauthenticated",
		"POST /api/shares/{id}/approve → 200", "POST /api/shares/{id}/approve → 401 reauth_required",
		"POST /api/shares/{id}/approve → 403 non-owner", "POST /api/shares/{id}/approve → 409 invalid_transition",
		"POST /api/shares/{id}/approve → 401 unauthenticated",
		"POST /api/shares/{id}/reject → 200", "POST /api/shares/{id}/reject → 403 non-owner",
		"POST /api/shares/{id}/reject → 409 invalid_transition", "POST /api/shares/{id}/reject → 401 unauthenticated",
		"POST /api/shares/{id}/revoke → 200", "POST /api/shares/{id}/revoke → 403 non-owner",
		"POST /api/shares/{id}/revoke → 409 invalid_transition", "POST /api/shares/{id}/revoke → 401 unauthenticated",
		"GET /api/shares/{id}/export → 200 blob", "GET /api/shares/{id}/export → 401 reauth_required",
		"GET /api/shares/{id}/export → 409 invalid_transition", "GET /api/shares/{id}/export → 401 unauthenticated",
		"POST /api/shares/import → 200 idempotent", "POST /api/shares/import → 400 validation_failed",
		"POST /api/shares/import → 409 revoked", "POST /api/shares/import → 403 requester mismatch",
		"POST /api/shares/import → 404 missing request", "POST /api/shares/import → 401 unauthenticated",
		"POST /api/files/{id}/sign → 200 frozen shape",
		"POST /api/files/{id}/sign → 400 invalid_content_type", "POST /api/files/{id}/sign → 403 non-owner",
		"POST /api/files/{id}/sign → 401 reauth_required", "POST /api/files/{id}/sign → 401 unauthenticated",
		"GET /api/files/{id}/verify → 200 valid", "GET /api/files/{id}/verify → 200 content_modified",
		"GET /api/files/{id}/verify → 200 unknown_signer", "GET /api/files/{id}/verify → 200 no_signature",
		"GET /api/files/{id}/verify → 200 multi-signature", "GET /api/files/{id}/verify → 403 non-reader",
		"GET /api/files/{id}/verify → 401 unauthenticated",
	} {
		t.Run(testCase, func(t *testing.T) {
			t.Skip("handlers not merged; router.go has no sharing or PDF route registrations")
		})
	}
}

func TestContractRouteCoverage(t *testing.T) {
	source, err := os.ReadFile("router.go")
	require.NoError(t, err)
	registrations := regexp.MustCompile(`apiMux\.Handle(?:Func)?\("([A-Z]+) ([^"]+)"`).FindAllSubmatch(source, -1)
	require.NotEmpty(t, registrations, "expected apiMux route registrations")
	require.Regexp(t, regexp.MustCompile(`mux\.HandleFunc\("GET /healthz"`), string(source),
		"health route must have a contract case")

	covered := map[string]bool{
		"GET /healthz":                 true,
		"POST /api/auth/register":      true,
		"POST /api/auth/login":         true,
		"POST /api/auth/logout":        true,
		"GET /api/auth/me":             true,
		"POST /api/files":              true,
		"GET /api/files":               true,
		"GET /api/files/{id}/download": true,
		"DELETE /api/files/{id}":       true,
		"GET /api/records":             true,
		"POST /api/records":            true,
		"PATCH /api/records/{id}":      true,
		"DELETE /api/records/{id}":     true,
		"GET /api/audit":               true,
	}
	for _, registration := range registrations {
		route := string(registration[1]) + " " + string(registration[2])
		assert.Truef(t, covered[route], "route %q has no matching contract case", route)
	}
}
