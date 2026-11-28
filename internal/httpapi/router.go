package httpapi

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"time"

	"github.com/ilhmpbta/CypherSecurity/internal/config"
	"github.com/ilhmpbta/CypherSecurity/internal/httpapi/handlers"
	"github.com/ilhmpbta/CypherSecurity/internal/httpapi/middleware"
	"github.com/ilhmpbta/CypherSecurity/internal/keys"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
	"github.com/ilhmpbta/CypherSecurity/web"
)

type Deps struct {
	AuthSvc      handlers.AuthService
	FileSvc      handlers.FileService
	RecordSvc    handlers.RecordService
	AuditSvc     handlers.AuditService
	SharingSvc   handlers.SharingService
	KeysSvc      keys.Service
	UserRepo     repository.UserRepo
	SessionStore middleware.SessionStore
	Config       *config.Config
	HealthCheck  func(ctx context.Context) error
}

// NewRouter returns the root HTTP handler wiring all routes and middleware.
func NewRouter(deps Deps) http.Handler {
	secureCookies := true
	jsonLimit := int64(1 << 20)
	uploadLimit := int64(32 << 20)

	if deps.Config != nil {
		secureCookies = deps.Config.SecureCookies
		if deps.Config.MaxJSONBodyBytes > 0 {
			jsonLimit = deps.Config.MaxJSONBodyBytes
		}
		if deps.Config.MaxUploadBytes > 0 {
			uploadLimit = deps.Config.MaxUploadBytes
		}
	}

	authHandler := handlers.NewAuthHandler(deps.AuthSvc, deps.UserRepo, secureCookies)
	const multipartRAMBuffer = 4 << 20 // 4 MiB in-memory multipart buffer; upload cap is enforced by uploadBodyMW using Config.MaxUploadBytes.
	filesHandler := handlers.NewFilesHandler(deps.FileSvc, multipartRAMBuffer)
	recordsHandler := handlers.NewRecordsHandler(deps.RecordSvc)
	auditHandler := handlers.NewAuditHandler(deps.AuditSvc)
	var sharesHandler *handlers.SharesHandler
	if deps.SharingSvc != nil {
		sharesHandler = handlers.NewSharesHandler(deps.SharingSvc)
	}

	mux := http.NewServeMux()

	// Health check (no middleware, no rate limit, no CSRF)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if deps.HealthCheck != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			if err := deps.HealthCheck(ctx); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "degraded", "error": "database unreachable"})
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	apiMux := http.NewServeMux()

	apply := func(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
		for i := len(mws) - 1; i >= 0; i-- {
			h = mws[i](h)
		}
		return h
	}

	sessionMW := middleware.Session(deps.SessionStore, deps.UserRepo)
	jsonBodyMW := middleware.MaxBodyBytes(jsonLimit)
	uploadBodyMW := middleware.MaxBodyBytes(uploadLimit)

	// Auth routes
	apiMux.Handle("POST /api/auth/register", apply(http.HandlerFunc(authHandler.Register), jsonBodyMW))
	apiMux.Handle("POST /api/auth/login", apply(http.HandlerFunc(authHandler.Login), jsonBodyMW))
	apiMux.Handle("POST /api/auth/logout", apply(http.HandlerFunc(authHandler.Logout), jsonBodyMW))
	apiMux.Handle("GET /api/auth/me", apply(http.HandlerFunc(authHandler.Me), sessionMW))

	// File routes
	apiMux.Handle("POST /api/files", apply(http.HandlerFunc(filesHandler.Upload), uploadBodyMW, sessionMW))
	apiMux.Handle("GET /api/files", apply(http.HandlerFunc(filesHandler.List), sessionMW))
	apiMux.Handle("GET /api/files/{id}/download", apply(http.HandlerFunc(filesHandler.Download), sessionMW))
	apiMux.Handle("DELETE /api/files/{id}", apply(http.HandlerFunc(filesHandler.Delete), sessionMW))
	apiMux.Handle("POST /api/files/{id}/sign", apply(http.HandlerFunc(filesHandler.Sign), sessionMW))
	apiMux.Handle("GET /api/files/{id}/verify", apply(http.HandlerFunc(filesHandler.Verify), sessionMW))

	// Sharing routes
	if sharesHandler != nil {
		apiMux.Handle("POST /api/shares", apply(http.HandlerFunc(sharesHandler.CreateRequest), jsonBodyMW, sessionMW))
		apiMux.Handle("GET /api/shares/inbox", apply(http.HandlerFunc(sharesHandler.ListInbox), sessionMW))
		apiMux.Handle("GET /api/shares/outgoing", apply(http.HandlerFunc(sharesHandler.ListOutgoing), sessionMW))
		apiMux.Handle("POST /api/shares/{id}/approve", apply(http.HandlerFunc(sharesHandler.Approve), sessionMW))
		apiMux.Handle("POST /api/shares/{id}/reject", apply(http.HandlerFunc(sharesHandler.Reject), sessionMW))
		apiMux.Handle("POST /api/shares/{id}/revoke", apply(http.HandlerFunc(sharesHandler.Revoke), sessionMW))
		apiMux.Handle("GET /api/shares/{id}/export", apply(http.HandlerFunc(sharesHandler.Export), sessionMW))
		apiMux.Handle("POST /api/shares/import", apply(http.HandlerFunc(sharesHandler.Import), sessionMW))
	}

	// Record routes
	apiMux.Handle("GET /api/records", apply(http.HandlerFunc(recordsHandler.List), sessionMW))
	apiMux.Handle("POST /api/records", apply(http.HandlerFunc(recordsHandler.Create), jsonBodyMW, sessionMW))
	apiMux.Handle("PATCH /api/records/{id}", apply(http.HandlerFunc(recordsHandler.Update), jsonBodyMW, sessionMW))
	apiMux.Handle("DELETE /api/records/{id}", apply(http.HandlerFunc(recordsHandler.Delete), sessionMW))

	// Audit routes
	apiMux.Handle("GET /api/audit", apply(http.HandlerFunc(auditHandler.List), sessionMW))

	ratelimitMW := middleware.RateLimit(50.0, 100)
	csrfMW := middleware.CSRF(secureCookies)

	mux.Handle("/api/", ratelimitMW(csrfMW(apiMux)))

	sub, err := fs.Sub(web.Dist, "dist")
	if err == nil {
		static := http.FileServer(http.FS(sub))

		mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}

			static.ServeHTTP(w, r)
		}))
	}

	return mux
}
