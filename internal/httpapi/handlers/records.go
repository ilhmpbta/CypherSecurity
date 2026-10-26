package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/httpapi/middleware"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
)

type RecordsHandler struct {
	recordSvc RecordService
}

func NewRecordsHandler(recordSvc RecordService) *RecordsHandler {
	return &RecordsHandler{recordSvc: recordSvc}
}

func (h *RecordsHandler) List(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok || user == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	records, err := h.recordSvc.List(r.Context(), user.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "list failed")
		return
	}

	projected := make([]map[string]any, len(records))
	for i, r := range records {
		projected[i] = map[string]any{
			"id":         r.ID,
			"data_type":  r.DataType,
			"payload":    r.Payload,
			"created_at": r.CreatedAt,
			"updated_at": r.UpdatedAt,
		}
	}
	respondJSON(w, http.StatusOK, map[string]any{"records": projected})
}

type recordRequest struct {
	DataType string         `json:"data_type"`
	Payload  map[string]any `json:"payload"`
}

func (h *RecordsHandler) Create(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok || user == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req recordRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		if middleware.CheckMaxBytesError(w, err) {
			return
		}
		respondError(w, http.StatusBadRequest, "invalid request")
		return
	}

	req.DataType = strings.TrimSpace(req.DataType)
	if req.DataType == "" {
		respondError(w, http.StatusBadRequest, "data_type is required")
		return
	}

	rec, err := h.recordSvc.Create(r.Context(), user.ID, req.DataType, req.Payload)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "create failed")
		return
	}

	respondJSON(w, http.StatusCreated, map[string]any{
		"id":         rec.ID,
		"data_type":  rec.DataType,
		"payload":    rec.Payload,
		"created_at": rec.CreatedAt,
		"updated_at": rec.UpdatedAt,
	})
}

func (h *RecordsHandler) Update(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok || user == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	idStr := r.PathValue("id")
	recordID, err := uuid.Parse(idStr)
	if err != nil {
		respondError(w, http.StatusNotFound, "not found")
		return
	}

	var req recordRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		if middleware.CheckMaxBytesError(w, err) {
			return
		}
		respondError(w, http.StatusBadRequest, "invalid request")
		return
	}

	req.DataType = strings.TrimSpace(req.DataType)
	if req.DataType == "" {
		respondError(w, http.StatusBadRequest, "data_type is required")
		return
	}

	rec, err := h.recordSvc.Update(r.Context(), recordID, user.ID, req.DataType, req.Payload)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		respondError(w, http.StatusNotFound, "not found")
		return
	case err != nil:
		respondError(w, http.StatusInternalServerError, "update failed")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"id":         rec.ID,
		"data_type":  rec.DataType,
		"payload":    rec.Payload,
		"created_at": rec.CreatedAt,
		"updated_at": rec.UpdatedAt,
	})
}

func (h *RecordsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok || user == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	idStr := r.PathValue("id")
	recordID, err := uuid.Parse(idStr)
	if err != nil {
		respondError(w, http.StatusNotFound, "not found")
		return
	}

	err = h.recordSvc.Delete(r.Context(), recordID, user.ID)
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
