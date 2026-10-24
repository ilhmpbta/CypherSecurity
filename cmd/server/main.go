package main

import (
	"context"
	"log"

	"github.com/joho/godotenv"

	"github.com/ilhmpbta/CypherSecurity/internal/config"
	"github.com/ilhmpbta/CypherSecurity/internal/migrations"
	"github.com/ilhmpbta/CypherSecurity/internal/repository/postgres"
)

func main() {
	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx := context.Background()

	pool, err := postgres.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer pool.Close()

	if err := migrations.Migrate(ctx, pool); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	log.Printf("cyphersecurity: ready on %s", cfg.HTTPAddr)
}