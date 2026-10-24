package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/ilhmpbta/CypherSecurity/internal/migrations"
)

func TestMigrate_CreatesTablesAndIsIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx := context.Background()

	pgc, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("cypher"),
		postgres.WithUsername("cypher"),
		postgres.WithPassword("cypher"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pgc.Terminate(context.Background()) })

	connStr, err := pgc.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	pool, err := pgxpool.New(ctx, connStr)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	// 1st run: creates everything
	require.NoError(t, migrations.Migrate(ctx, pool))

	for _, table := range []string{
		"users", "personal_records", "stored_files",
		"audit_events", "sessions", "schema_migrations",
	} {
		var exists bool
		err := pool.QueryRow(ctx,
			`SELECT EXISTS (
			   SELECT 1 FROM information_schema.tables
			   WHERE table_schema='public' AND table_name=$1
			 )`, table).Scan(&exists)
		require.NoError(t, err)
		require.True(t, exists, "table %s missing", table)
	}

	// 2nd run: no-op
	require.NoError(t, migrations.Migrate(ctx, pool))

	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&n))
	require.Equal(t, 2, n, "expected exactly 2 applied migrations")
}
