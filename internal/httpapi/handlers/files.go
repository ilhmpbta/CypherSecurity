package handlers

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/httpapi/middleware"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
)

type FilesHandler struct {
	fileSvc   FileService
	maxMemory int64
}

func NewFilesHandler(fileSvc FileService, maxMemory int64) *FilesHandler {
	if maxMemory <= 0 {
		maxMemory = 4 << 20 // 4MB default RAM buffer for multipart parsing
	}
	return &FilesHandler{fileSvc: fileSvc, maxMemory: maxMemory}
}

func (h *FilesHandler) Upload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(h.maxMemory); err != nil {
		if middleware.CheckMaxBytesError(w, err) {
			return
		}
		respondError(w, http.StatusBadRequest, "invalid multipart request")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		respondError(w, http.StatusBadRequest, "missing file field")
		return
	}
	defer func() {
		_ = file.Close()
	}()

	user, ok := middleware.UserFromContext(r.Context())
	if !ok || user == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	contentType := header.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	savedFile, err := h.fileSvc.Upload(r.Context(), user.ID, file, contentType, header.Filename)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "upload failed")
		return
	}

	respondJSON(w, http.StatusCreated, map[string]any{
		"id":             savedFile.ID,
		"original_name":  savedFile.OriginalName,
		"content_type":   savedFile.ContentType,
		"plaintext_size": savedFile.PlaintextSize,
		"created_at":     savedFile.CreatedAt,
	})
}

func (h *FilesHandler) List(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok || user == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	files, err := h.fileSvc.List(r.Context(), user.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "list failed")
		return
	}

	projected := make([]map[string]any, len(files))
	for i, f := range files {
		projected[i] = map[string]any{
			"id":             f.ID,
			"original_name":  f.OriginalName,
			"content_type":   f.ContentType,
			"plaintext_size": f.PlaintextSize,
			"created_at":     f.CreatedAt,
		}
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"files": projected,
	})
}

func (h *FilesHandler) Download(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok || user == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	idStr := r.PathValue("id")
	fileID, err := uuid.Parse(idStr)
	if err != nil {
		respondError(w, http.StatusNotFound, "not found")
		return
	}

	reader, fileMeta, err := h.fileSvc.Download(r.Context(), fileID, user.ID)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		respondError(w, http.StatusNotFound, "not found")
		return
	case err != nil:
		respondError(w, http.StatusInternalServerError, "download failed")
		return
	}

	if reader == nil {
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer func() {
		_ = reader.Close()
	}()

	// Sanitize filename for Content-Disposition
	filename := fileMeta.OriginalName
	filename = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r < 32 || r == '"' || r == '\\' {
			return '_'
		}
		return r
	}, filename)
	if filename == "" {
		filename = "download"
	}

	w.Header().Set("Content-Type", fileMeta.ContentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	if fileMeta.PlaintextSize > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(fileMeta.PlaintextSize, 10))
	}
	w.WriteHeader(http.StatusOK)

	_, _ = io.Copy(w, reader)
}

func (h *FilesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok || user == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	idStr := r.PathValue("id")
	fileID, err := uuid.Parse(idStr)
	if err != nil {
		respondError(w, http.StatusNotFound, "not found")
		return
	}

	err = h.fileSvc.Delete(r.Context(), fileID, user.ID)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		respondError(w, http.StatusNotFound, "not found")
		return
	case err != nil:
		respondError(w, http.StatusInternalServerError, "delete failed")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
