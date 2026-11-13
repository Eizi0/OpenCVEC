// Package testdb fournit une base PostgreSQL isolée aux tests d'intégration.
//
// Les tests sont ignorés si OPENCVEC_TEST_DATABASE_URL n'est pas définie. Chaque appel crée un
// schéma dédié (migrations comprises), supprimé à la fin du test : les tests peuvent tourner
// en parallèle sur la même base sans s'influencer.
package testdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Eizi0/OpenCVEC/internal/store"
)

// New ouvre un pool sur un schéma neuf et migré.
func New(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("OPENCVEC_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("OPENCVEC_TEST_DATABASE_URL non définie : test d'intégration ignoré")
	}
	ctx := context.Background()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	schema := "test_" + hex.EncodeToString(b)

	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
		admin.Close()
	})
	if err := (&store.Store{Pool: pool}).Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return pool
}
