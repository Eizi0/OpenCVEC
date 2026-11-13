package httpapi

import (
	"context"
	"crypto/sha256"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// rlDB est l'accès base utilisé par les limiteurs partagés.
type rlDB interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// limiter compte les tentatives par clé (adresse IP, adresse e-mail) sur une fenêtre fixe.
// Avec une base, les compteurs sont partagés entre toutes les instances d'OpenCVEC (table
// rate_limits) ; sans base, ou si elle ne répond pas, ils restent en mémoire.
type limiter struct {
	name   string
	db     rlDB
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string]*bucket
	last   time.Time
}

type bucket struct {
	count int
	reset time.Time
}

func newLimiter(name string, db rlDB, max int, window time.Duration) *limiter {
	return &limiter{name: name, db: db, max: max, window: window, hits: map[string]*bucket{}}
}

func keyHash(key string) []byte {
	h := sha256.Sum256([]byte(key))
	return h[:]
}

// allow enregistre une tentative et indique si elle est autorisée, avec le délai d'attente sinon.
func (l *limiter) allow(key string, now time.Time) (bool, time.Duration) {
	if l.db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		var hits int
		var reset time.Time
		err := l.db.QueryRow(ctx, `INSERT INTO rate_limits (bucket, key_hash, hits, reset_at) VALUES ($1, $2, 1, $3)
			ON CONFLICT (bucket, key_hash) DO UPDATE SET
				hits = CASE WHEN rate_limits.reset_at <= $4 THEN 1 ELSE rate_limits.hits + 1 END,
				reset_at = CASE WHEN rate_limits.reset_at <= $4 THEN EXCLUDED.reset_at ELSE rate_limits.reset_at END
			RETURNING hits, reset_at`, l.name, keyHash(key), now.Add(l.window), now).Scan(&hits, &reset)
		if err == nil {
			if hits > l.max {
				return false, reset.Sub(now)
			}
			return true, 0
		}
		// Base indisponible : on retombe sur le compteur en mémoire plutôt que de tout bloquer.
	}
	return l.allowMem(key, now)
}

func (l *limiter) allowMem(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.last) > l.window { // ménage périodique
		for k, b := range l.hits {
			if now.After(b.reset) {
				delete(l.hits, k)
			}
		}
		l.last = now
	}
	b := l.hits[key]
	if b == nil || now.After(b.reset) {
		b = &bucket{reset: now.Add(l.window)}
		l.hits[key] = b
	}
	b.count++
	if b.count > l.max {
		return false, b.reset.Sub(now)
	}
	return true, 0
}

// reset efface le compteur d'une clé (connexion réussie).
func (l *limiter) reset(key string) {
	if l.db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = l.db.Exec(ctx, `DELETE FROM rate_limits WHERE bucket = $1 AND key_hash = $2`, l.name, keyHash(key))
	}
	l.mu.Lock()
	delete(l.hits, key)
	l.mu.Unlock()
}

// Limiteurs de l'instance : connexions et second facteur.
type limits struct {
	loginIP    *limiter
	loginEmail *limiter
	totpIP     *limiter
}

func newLimits(db rlDB) *limits {
	return &limits{
		loginIP:    newLimiter("login_ip", db, 20, 15*time.Minute),
		loginEmail: newLimiter("login_email", db, 8, 15*time.Minute),
		totpIP:     newLimiter("totp_ip", db, 30, 15*time.Minute),
	}
}

func tooMany(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
	writeErr(w, http.StatusTooManyRequests, "trop de tentatives : réessayez dans "+strconv.Itoa(int(wait.Minutes())+1)+" minute(s)")
}
