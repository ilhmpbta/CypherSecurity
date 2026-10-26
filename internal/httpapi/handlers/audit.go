package handlers

import (
	"net/http"
	"strconv"

	"github.com/ilhmpbta/CypherSecurity/internal/httpapi/middleware"
)

type AuditHandler struct {
	auditSvc AuditService
}

func NewAuditHandler(auditSvc AuditService) *AuditHandler {
	return &AuditHandler{auditSvc: auditSvc}
}

func (h *AuditHandler) List(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok || user == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
			if limit > 200 {
				limit = 200
			}
		}
	}

	events, err := h.auditSvc.ListByActor(r.Context(), user.ID, limit)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "audit list failed")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"events": events,
	})
}
