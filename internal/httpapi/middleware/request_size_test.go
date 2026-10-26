package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequestSizeMiddleware(t *testing.T) {
	handler := MaxBodyBytes(5)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if CheckMaxBytesError(w, err) {
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Small body -> OK
	req := httptest.NewRequest("POST", "/", strings.NewReader("12345"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Large body (> 5 bytes) -> 413
	req = httptest.NewRequest("POST", "/", strings.NewReader("123456"))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}
