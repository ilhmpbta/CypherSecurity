package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/httpapi/middleware"
	"github.com/ilhmpbta/CypherSecurity/internal/keys"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
	"github.com/ilhmpbta/CypherSecurity/internal/sharing"
)

type SharesHandler struct {
	sharingSvc SharingService
}

func NewSharesHandler(sharingSvc SharingService) *SharesHandler {
	return &SharesHandler{sharingSvc: sharingSvc}
}

type createShareRequestPayload struct {
	FileID uuid.UUID `json:"file_id"`
	Note   string    `json:"note"`
}

func (h *SharesHandler) CreateRequest(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok || user == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var payload createShareRequestPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	if payload.FileID == uuid.Nil {
		respondError(w, http.StatusBadRequest, "invalid_file_id")
		return
	}

	req, created, err := h.sharingSvc.Request(r.Context(), user.ID, payload.FileID, payload.Note)
	switch {
	case errors.Is(err, sharing.ErrNotFound) || errors.Is(err, repository.ErrNotFound):
		respondError(w, http.StatusNotFound, "not_found")
		return
	case errors.Is(err, sharing.ErrForbidden):
		respondError(w, http.StatusForbidden, "forbidden")
		return
	case err != nil:
		respondError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	status := http.StatusCreated
	if !created {
		status = http.StatusOK
	}

	respondJSON(w, status, req)
}

func (h *SharesHandler) ListInbox(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok || user == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	statusFilter := r.URL.Query().Get("status")
	list, err := h.sharingSvc.ListInbox(r.Context(), user.ID, statusFilter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if list == nil {
		list = []sharing.ShareRequest{}
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"shares": list,
	})
}

func (h *SharesHandler) ListOutgoing(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok || user == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	statusFilter := r.URL.Query().Get("status")
	list, err := h.sharingSvc.ListOutgoing(r.Context(), user.ID, statusFilter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if list == nil {
		list = []sharing.ShareRequest{}
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"shares": list,
	})
}

func (h *SharesHandler) Approve(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok || user == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	keysSess, _ := middleware.KeysSessionFromContext(r.Context())
	if len(keysSess.WrapKey) == 0 {
		respondError(w, http.StatusUnauthorized, "reauth_required")
		return
	}

	idStr := r.PathValue("id")
	shareID, err := uuid.Parse(idStr)
	if err != nil {
		respondError(w, http.StatusNotFound, "not_found")
		return
	}

	req, err := h.sharingSvc.Approve(r.Context(), shareID, keysSess)
	switch {
	case errors.Is(err, keys.ErrSessionLocked):
		respondError(w, http.StatusUnauthorized, "reauth_required")
		return
	case errors.Is(err, sharing.ErrNotFound) || errors.Is(err, repository.ErrNotFound):
		respondError(w, http.StatusNotFound, "not_found")
		return
	case errors.Is(err, sharing.ErrForbidden):
		respondError(w, http.StatusForbidden, "forbidden")
		return
	case errors.Is(err, sharing.ErrInvalidTransition):
		respondError(w, http.StatusConflict, "invalid_transition")
		return
	case err != nil:
		respondError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	respondJSON(w, http.StatusOK, req)
}

func (h *SharesHandler) Reject(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok || user == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	idStr := r.PathValue("id")
	shareID, err := uuid.Parse(idStr)
	if err != nil {
		respondError(w, http.StatusNotFound, "not_found")
		return
	}

	req, err := h.sharingSvc.Reject(r.Context(), shareID, user.ID)
	switch {
	case errors.Is(err, sharing.ErrNotFound) || errors.Is(err, repository.ErrNotFound):
		respondError(w, http.StatusNotFound, "not_found")
		return
	case errors.Is(err, sharing.ErrForbidden):
		respondError(w, http.StatusForbidden, "forbidden")
		return
	case errors.Is(err, sharing.ErrInvalidTransition):
		respondError(w, http.StatusConflict, "invalid_transition")
		return
	case err != nil:
		respondError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	respondJSON(w, http.StatusOK, req)
}

func (h *SharesHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok || user == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	idStr := r.PathValue("id")
	shareID, err := uuid.Parse(idStr)
	if err != nil {
		respondError(w, http.StatusNotFound, "not_found")
		return
	}

	req, err := h.sharingSvc.Revoke(r.Context(), shareID, user.ID)
	switch {
	case errors.Is(err, sharing.ErrNotFound) || errors.Is(err, repository.ErrNotFound):
		respondError(w, http.StatusNotFound, "not_found")
		return
	case errors.Is(err, sharing.ErrForbidden):
		respondError(w, http.StatusForbidden, "forbidden")
		return
	case errors.Is(err, sharing.ErrInvalidTransition):
		respondError(w, http.StatusConflict, "invalid_transition")
		return
	case err != nil:
		respondError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	respondJSON(w, http.StatusOK, req)
}

func (h *SharesHandler) Export(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok || user == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	keysSess, _ := middleware.KeysSessionFromContext(r.Context())
	if len(keysSess.WrapKey) == 0 {
		respondError(w, http.StatusUnauthorized, "reauth_required")
		return
	}

	idStr := r.PathValue("id")
	shareID, err := uuid.Parse(idStr)
	if err != nil {
		respondError(w, http.StatusNotFound, "not_found")
		return
	}

	blob, filename, err := h.sharingSvc.Export(r.Context(), shareID, keysSess)
	switch {
	case errors.Is(err, keys.ErrSessionLocked):
		respondError(w, http.StatusUnauthorized, "reauth_required")
		return
	case errors.Is(err, sharing.ErrNotFound) || errors.Is(err, repository.ErrNotFound):
		respondError(w, http.StatusNotFound, "not_found")
		return
	case errors.Is(err, sharing.ErrForbidden):
		respondError(w, http.StatusForbidden, "forbidden")
		return
	case errors.Is(err, sharing.ErrInvalidTransition):
		respondError(w, http.StatusConflict, "invalid_transition")
		return
	case err != nil:
		respondError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	sanitized := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r < 32 || r == '"' || r == '\\' {
			return '_'
		}
		return r
	}, filename)
	if sanitized == "" {
		sanitized = "share"
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+sanitized+`.cskey"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(blob)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(blob)
}

func (h *SharesHandler) Import(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok || user == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	ct := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if ct != "application/octet-stream" {
		respondError(w, http.StatusBadRequest, "invalid_content_type")
		return
	}

	// Limit read to MaxBlobSize + 1 to detect overly large payloads
	limitedReader := io.LimitReader(r.Body, sharing.MaxBlobSize+1)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		respondError(w, http.StatusBadRequest, "read_failed")
		return
	}

	if len(body) > sharing.MaxBlobSize {
		respondError(w, http.StatusRequestEntityTooLarge, "too_large")
		return
	}

	if len(body) < sharing.MinBlobSize {
		respondError(w, http.StatusBadRequest, "validation_failed")
		return
	}

	req, err := h.sharingSvc.Import(r.Context(), user.ID, body)
	switch {
	case errors.Is(err, sharing.ErrTooLarge):
		respondError(w, http.StatusRequestEntityTooLarge, "too_large")
		return
	case errors.Is(err, sharing.ErrNotFound) || errors.Is(err, repository.ErrNotFound):
		respondError(w, http.StatusNotFound, "not_found")
		return
	case errors.Is(err, sharing.ErrForbidden):
		respondError(w, http.StatusForbidden, "forbidden")
		return
	case errors.Is(err, sharing.ErrInvalidTransition):
		respondError(w, http.StatusConflict, "invalid_transition")
		return
	case errors.Is(err, sharing.ErrValidationFailed):
		respondError(w, http.StatusBadRequest, "validation_failed")
		return
	case err != nil:
		respondError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	respondJSON(w, http.StatusOK, req)
}
