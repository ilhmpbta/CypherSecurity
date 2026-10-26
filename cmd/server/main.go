package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt" // ← added
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"github.com/ilhmpbta/CypherSecurity/internal/audit"
	"github.com/ilhmpbta/CypherSecurity/internal/auth"
	"github.com/ilhmpbta/CypherSecurity/internal/config"
	"github.com/ilhmpbta/CypherSecurity/internal/crypto/production"
	"github.com/ilhmpbta/CypherSecurity/internal/files"
	"github.com/ilhmpbta/CypherSecurity/internal/httpapi"
	"github.com/ilhmpbta/CypherSecurity/internal/migrations"
	"github.com/ilhmpbta/CypherSecurity/internal/records"
	"github.com/ilhmpbta/CypherSecurity/internal/repository/postgres"
	"github.com/ilhmpbta/CypherSecurity/internal/storage"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := postgres.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("db: %w", err)
	}
	defer pool.Close()

	if err := migrations.Migrate(ctx, pool); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	// KEK
	kekBytes, err := base64.StdEncoding.DecodeString(cfg.KEKBase64)
	if err != nil {
		kekBytes, err = base64.RawStdEncoding.DecodeString(cfg.KEKBase64)
		if err != nil {
			return fmt.Errorf("decode CYPHER_KEK: %w", err)
		}
	}
	km, err := production.New(map[int][]byte{1: kekBytes})
	if err != nil {
		return fmt.Errorf("KeyManager: %w", err)
	}

	// Storage
	fs, err := storage.NewFS(cfg.StorageRoot)
	if err != nil {
		return fmt.Errorf("storage: %w", err)
	}

	// Repos
	userRepo := postgres.NewUserRepo(pool)
	fileRepo := postgres.NewFileRepo(pool)
	recordRepo := postgres.NewPersonalRecordRepo(pool)
	auditRepo := postgres.NewAuditRepo(pool)
	sessionRepo := postgres.NewSessionRepo(pool)

	// Services
	auditLogger := audit.NewLogger(auditRepo)
	sessionStore := auth.NewSessionStore(sessionRepo)
	authSvc := auth.NewService(userRepo, sessionStore, auditLogger)
	fileSvc := files.NewService(fileRepo, fs, km, auditLogger)
	recordSvc := records.NewService(recordRepo)

	// Router
	router := httpapi.NewRouter(httpapi.Deps{
		AuthSvc:      authSvc,
		FileSvc:      fileSvc,
		RecordSvc:    recordSvc,
		AuditSvc:     auditLogger,
		UserRepo:     userRepo,
		SessionStore: sessionStore,
		Config:       cfg,
		HealthCheck:  func(ctx context.Context) error { return pool.Ping(ctx) },
	})

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("cyphersecurity: listening on %s", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("listen: %w", err) // server already stopped; no Shutdown needed
	case <-ctx.Done():
		log.Println("cyphersecurity: shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}
