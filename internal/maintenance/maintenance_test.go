package maintenance

import (
	"context"
	"testing"
	"time"

	"github.com/Eizi0/OpenCVEC/internal/testdb"
)

func TestPurgeKeepsProofsAndAlerts(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	old := time.Now().Add(-400 * 24 * time.Hour)
	for _, st := range []string{"unknown", "selftest", "expired", "replay", "duplicate", "correlated", "honeytoken"} {
		if _, err := db.Exec(ctx, `INSERT INTO callbacks (received_at, proto, qname, source_ip, status) VALUES ($1, 'dns', 'x', '1.2.3.4', $2)`, old, st); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(ctx, `INSERT INTO callbacks (proto, qname, source_ip, status) VALUES ('dns', 'récent', '1.2.3.4', 'unknown')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO reports (title, format, content, sha256, created_at) VALUES ('r', 'json', '{}', 'x', $1)`, old); err != nil {
		t.Fatal(err)
	}
	r, err := Purge(ctx, db, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if r.Callbacks != 5 || r.Reports != 1 {
		t.Fatalf("purge : %+v", r)
	}
	var left []string
	rows, _ := db.Query(ctx, `SELECT status FROM callbacks ORDER BY id`)
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		left = append(left, s)
	}
	rows.Close()
	if len(left) != 3 || left[0] != "correlated" || left[1] != "honeytoken" || left[2] != "unknown" {
		t.Fatalf("restants : %v (preuves, alertes et bruit récent doivent rester)", left)
	}
	// Conservation illimitée : rien n'est purgé.
	if _, err := db.Exec(ctx, `INSERT INTO settings (key, value) VALUES ('general', '{"retention_days":0}')`); err != nil {
		t.Fatal(err)
	}
	_, _ = db.Exec(ctx, `INSERT INTO callbacks (received_at, proto, qname, source_ip, status) VALUES ($1, 'dns', 'x', '1.2.3.4', 'unknown')`, old)
	if r, _ := Purge(ctx, db, time.Now()); r.Callbacks != 0 {
		t.Fatal("conservation illimitée non respectée")
	}
}
