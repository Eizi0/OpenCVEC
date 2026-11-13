// Package audit écrit et vérifie le journal d'audit chaîné.
//
// Chaque entrée porte l'empreinte de la précédente : hash = SHA-256(prev_hash || contenu).
// Un déclencheur PostgreSQL interdit UPDATE et DELETE ; Verify détecte en plus toute
// altération faite en contournant ce déclencheur (accès direct au disque, restauration partielle).
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Entry est une ligne du journal.
type Entry struct {
	ID     int64     `json:"id"`
	At     time.Time `json:"at"`
	UserID *int64    `json:"user_id,omitempty"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Detail string    `json:"detail"`
	IP     string    `json:"ip"`
	Hash   string    `json:"hash"`
}

// Log écrit dans le journal.
type Log struct{ DB *pgxpool.Pool }

func digest(prev []byte, at time.Time, userID *int64, actor, action, detail, ip string) []byte {
	h := sha256.New()
	h.Write(prev)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(at.UTC().UnixMicro()))
	h.Write(b[:])
	var uid int64
	if userID != nil {
		uid = *userID
	}
	binary.BigEndian.PutUint64(b[:], uint64(uid))
	h.Write(b[:])
	for _, s := range []string{actor, action, detail, ip} {
		binary.BigEndian.PutUint64(b[:], uint64(len(s)))
		h.Write(b[:])
		h.Write([]byte(s))
	}
	return h.Sum(nil)
}

// Write ajoute une entrée. Un verrou transactionnel sérialise les écritures pour que la chaîne reste linéaire.
func (l *Log) Write(ctx context.Context, userID *int64, actor, action, detail, ip string) error {
	return pgx.BeginFunc(ctx, l.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(727303)`); err != nil {
			return err
		}
		prev := make([]byte, 32)
		err := tx.QueryRow(ctx, `SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&prev)
		if err != nil && err != pgx.ErrNoRows {
			return err
		}
		// Précision microseconde, comme PostgreSQL, pour que la vérification recalcule la même empreinte.
		at := time.Now().UTC().Truncate(time.Microsecond)
		h := digest(prev, at, userID, actor, action, detail, ip)
		_, err = tx.Exec(ctx, `INSERT INTO audit_log (at, user_id, actor, action, detail, ip, prev_hash, hash)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, at, userID, actor, action, detail, ip, prev, h)
		return err
	})
}

// VerifyResult résume la vérification de la chaîne.
type VerifyResult struct {
	OK       bool   `json:"ok"`
	Count    int64  `json:"count"`
	BrokenAt int64  `json:"broken_at,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// Verify recalcule toute la chaîne.
func (l *Log) Verify(ctx context.Context) (VerifyResult, error) {
	rows, err := l.DB.Query(ctx, `SELECT id, at, user_id, actor, action, detail, ip, prev_hash, hash FROM audit_log ORDER BY id`)
	if err != nil {
		return VerifyResult{}, err
	}
	defer rows.Close()
	prev := make([]byte, 32)
	var n int64
	for rows.Next() {
		var id int64
		var at time.Time
		var uid *int64
		var actor, action, detail, ip string
		var p, h []byte
		if err := rows.Scan(&id, &at, &uid, &actor, &action, &detail, &ip, &p, &h); err != nil {
			return VerifyResult{}, err
		}
		n++
		if !bytes.Equal(p, prev) {
			return VerifyResult{Count: n, BrokenAt: id, Reason: "maillon manquant ou réordonné"}, nil
		}
		if !bytes.Equal(digest(p, at, uid, actor, action, detail, ip), h) {
			return VerifyResult{Count: n, BrokenAt: id, Reason: "contenu modifié"}, nil
		}
		prev = h
	}
	if err := rows.Err(); err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{OK: true, Count: n}, nil
}

// Hex renvoie une empreinte courte lisible.
func Hex(b []byte) string { return fmt.Sprintf("%x", b) }
