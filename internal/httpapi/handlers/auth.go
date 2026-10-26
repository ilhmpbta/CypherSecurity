package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/auth"
	"github.com/ilhmpbta/CypherSecurity/internal/httpapi/middleware"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
)

type UserRepo interface {
	GetByUsername(ctx context.Context, username string) (repository.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (repository.User, error)
}

type AuthHandler struct {
	authSvc       AuthService
	userRepo      repository.UserRepo
	secureCookies bool
}

func NewAuthHandler(authSvc AuthService, userRepo repository.UserRepo, secureCookies bool) *AuthHandler {
	return &AuthHandler{
		authSvc:       authSvc,
		userRepo:      userRepo,
		secureCookies: secureCookies,
	}
}

type registerRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		if middleware.CheckMaxBytesError(w, err) {
			return
		}
		respondError(w, http.StatusBadRequest, "invalid request")
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		respondError(w, http.StatusBadRequest, "invalid request: username and password are required")
		return
	}

	user, err := h.authSvc.Register(r.Context(), req.Username, req.Password)
	if errors.Is(err, auth.ErrUsernameTaken) {
		respondError(w, http.StatusConflict, "username already taken")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}

	respondJSON(w, http.StatusCreated, map[string]any{
		"id":         user.ID,
		"username":   user.Username,
		"created_at": user.CreatedAt,
	})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		if middleware.CheckMaxBytesError(w, err) {
			return
		}
		respondError(w, http.StatusBadRequest, "invalid request")
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		respondError(w, http.StatusBadRequest, "invalid request: username and password are required")
		return
	}

	clientIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		clientIP = host
	}

	token, err := h.authSvc.Login(r.Context(), req.Username, req.Password, clientIP)
	if errors.Is(err, auth.ErrInvalidCredentials) {
		respondError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if errors.Is(err, auth.ErrThrottled) {
		respondError(w, http.StatusTooManyRequests, "too many failed login attempts")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Set session_id cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})

	user, err := h.userRepo.GetByUsername(r.Context(), req.Username)
	if err != nil {
		respondJSON(w, http.StatusOK, map[string]any{
			"ok": true,
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"user": map[string]any{
			"id":         user.ID,
			"username":   user.Username,
			"created_at": user.CreatedAt,
		},
	})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err == nil && cookie.Value != "" {
		_ = h.authSvc.Logout(r.Context(), cookie.Value)
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})

	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok || user == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"id":         user.ID,
		"username":   user.Username,
		"created_at": user.CreatedAt,
	})
}
