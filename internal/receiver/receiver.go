// Package receiver reçoit les callbacks des canaris (DNS autoritaire et HTTP) et les corrèle
// aux checks en cours.
package receiver

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Eizi0/OpenCVEC/internal/canary"
)

// Statuts d'un callback.
const (
	StatusCorrelated = "correlated"
	StatusDuplicate  = "duplicate"
	StatusExpired    = "expired"
	StatusReplay     = "replay"
	StatusUnknown    = "unknown"
	StatusSelftest   = "selftest"
	// StatusHoneytoken : le jeton d'un canari fichier est revenu hors de tout check (compromission probable).
	StatusHoneytoken = "honeytoken"
)

// Event est une requête reçue par le récepteur.
type Event struct {
	Proto  string // dns ou http
	QType  string // A, AAAA, GET…
	QName  string // nom interrogé ou hôte HTTP
	Source string // adresse IP de l'émetteur
	Raw    string // requête brute (tronquée)
	At     time.Time
}

// Hit est transmis au runner quand un canari est déclenché.
type Hit struct {
	CallbackID    int64
	At            time.Time
	Proto, QType  string
	QName, Point  string
	Source        string
	SourceMatches bool
}

// Correlator enregistre les événements et prévient les checks en attente.
type Correlator struct {
	DB     *pgxpool.Pool
	Signer *canary.Signer
	Zone   string
	Log    *slog.Logger

	// OnHoneytoken est appelé quand un canari fichier est lu hors d'un check.
	OnHoneytoken func(assetID int64, ev Event)

	mu       sync.Mutex
	waiters  map[int64]chan Hit
	selftest map[string]chan Event
	// fileWait associe un asset au check qui attend l'exfiltration de son canari fichier.
	fileWait map[int64]*fileWaiter

	noiseMu    sync.Mutex
	noiseCount int
	noiseReset time.Time
}

// Subscribe renvoie un canal qui recevra le premier callback corrélé du check.
func (c *Correlator) Subscribe(checkID int64) (<-chan Hit, func()) {
	ch := make(chan Hit, 1)
	c.mu.Lock()
	if c.waiters == nil {
		c.waiters = map[int64]chan Hit{}
	}
	c.waiters[checkID] = ch
	c.mu.Unlock()
	return ch, func() {
		c.mu.Lock()
		delete(c.waiters, checkID)
		c.mu.Unlock()
	}
}

type fileWaiter struct {
	checkID  int64
	consumed bool
}

// ExpectFile indique qu'un check attend le contenu du canari fichier de l'asset (exfiltration
// par DNS/HTTP). Pendant cette attente, le jeton n'est pas traité comme une alerte.
func (c *Correlator) ExpectFile(assetID, checkID int64) func() {
	c.mu.Lock()
	if c.fileWait == nil {
		c.fileWait = map[int64]*fileWaiter{}
	}
	c.fileWait[assetID] = &fileWaiter{checkID: checkID}
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		if w := c.fileWait[assetID]; w != nil && w.checkID == checkID {
			delete(c.fileWait, assetID)
		}
		c.mu.Unlock()
	}
}

// ExpectSelftest renvoie un canal qui recevra l'événement portant cette étiquette d'auto-test.
func (c *Correlator) ExpectSelftest(label string) (<-chan Event, func()) {
	ch := make(chan Event, 4)
	c.mu.Lock()
	if c.selftest == nil {
		c.selftest = map[string]chan Event{}
	}
	c.selftest[label] = ch
	c.mu.Unlock()
	return ch, func() {
		c.mu.Lock()
		delete(c.selftest, label)
		c.mu.Unlock()
	}
}

// allowNoise limite l'enregistrement des requêtes sans jeton valide (scan de la zone) à 120 par minute.
func (c *Correlator) allowNoise() bool {
	c.noiseMu.Lock()
	defer c.noiseMu.Unlock()
	now := time.Now()
	if now.After(c.noiseReset) {
		c.noiseReset = now.Add(time.Minute)
		c.noiseCount = 0
	}
	c.noiseCount++
	return c.noiseCount <= 120
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// Record traite un événement : il est ignoré s'il est hors zone, sinon enregistré avec son statut.
func (c *Correlator) Record(ctx context.Context, ev Event) (string, error) {
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	ev.Raw = truncate(ev.Raw, 2000)
	ev.QName = strings.ToLower(strings.TrimSuffix(ev.QName, "."))
	p, inZone := canary.Parse(ev.QName, c.Zone)
	if !inZone || ev.QName == c.Zone {
		return "", nil
	}
	first := strings.SplitN(ev.QName, ".", 2)[0]
	if strings.HasPrefix(first, "selftest-") {
		c.mu.Lock()
		ch := c.selftest[first]
		c.mu.Unlock()
		if ch != nil {
			select {
			case ch <- ev:
			default:
			}
		}
		_, err := c.DB.Exec(ctx, `INSERT INTO callbacks (received_at, proto, qtype, qname, source_ip, raw, status)
			VALUES ($1, $2, $3, $4, $5, $6, 'selftest')`, ev.At, ev.Proto, ev.QType, ev.QName, ev.Source, ev.Raw)
		return StatusSelftest, err
	}
	if p.Token == "" {
		return StatusUnknown, c.noise(ctx, ev, "")
	}

	var status string
	var hit Hit
	var checkID int64
	err := pgx.BeginFunc(ctx, c.DB, func(tx pgx.Tx) error {
		var assetID int64
		var expires time.Time
		var consumed *time.Time
		var checkStatus string
		var detail []byte
		err := tx.QueryRow(ctx, `SELECT c.check_id, c.asset_id, c.expires_at, c.consumed_at, k.status, k.detail
			FROM canaries c JOIN checks k ON k.id = c.check_id WHERE c.token = $1 FOR UPDATE OF c`, p.Token).
			Scan(&checkID, &assetID, &expires, &consumed, &checkStatus, &detail)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && !c.Signer.Verify(p.Token, assetID, checkID) {
			status = StatusUnknown
			checkID = 0
			return nil
		}
		if err != nil {
			return err
		}
		switch {
		case ev.At.After(expires):
			status = StatusExpired
		case checkStatus == "done" || checkStatus == "error" || checkStatus == "cancelled":
			status = StatusReplay
		case consumed != nil:
			status = StatusDuplicate
		default:
			status = StatusCorrelated
			if _, err := tx.Exec(ctx, `UPDATE canaries SET consumed_at = $2 WHERE token = $1`, p.Token, ev.At); err != nil {
				return err
			}
		}
		var d struct {
			ResolvedIPs []string `json:"resolved_ips"`
		}
		_ = json.Unmarshal(detail, &d)
		match := sourceMatches(ev.Source, d.ResolvedIPs)
		var id int64
		if err := tx.QueryRow(ctx, `INSERT INTO callbacks (received_at, proto, qtype, qname, point, source_ip, raw, token, check_id, status, source_matches)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id`,
			ev.At, ev.Proto, ev.QType, ev.QName, p.Point, ev.Source, ev.Raw, p.Token, checkID, status, match).Scan(&id); err != nil {
			return err
		}
		hit = Hit{CallbackID: id, At: ev.At, Proto: ev.Proto, QType: ev.QType, QName: ev.QName, Point: p.Point, Source: ev.Source, SourceMatches: match}
		return nil
	})
	if err != nil {
		return "", err
	}
	if status == StatusUnknown {
		if st, handled, err := c.fileToken(ctx, ev, p); handled || err != nil {
			return st, err
		}
		return status, c.noise(ctx, ev, p.Token)
	}
	if status == StatusCorrelated {
		c.mu.Lock()
		ch := c.waiters[checkID]
		c.mu.Unlock()
		if ch != nil {
			select {
			case ch <- hit:
			default:
			}
		}
	}
	return status, nil
}

// fileToken traite un jeton de canari fichier : preuve si un check l'attend, alerte sinon.
func (c *Correlator) fileToken(ctx context.Context, ev Event, p canary.Parsed) (string, bool, error) {
	var assetID int64
	var ips []string
	err := c.DB.QueryRow(ctx, `SELECT f.asset_id, a.resolved_ips FROM asset_canaries f JOIN assets a ON a.id = f.asset_id
		WHERE f.token = $1`, p.Token).Scan(&assetID, &ips)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	match := sourceMatches(ev.Source, ips)
	c.mu.Lock()
	w := c.fileWait[assetID]
	status, checkID := StatusHoneytoken, int64(0)
	if w != nil {
		checkID = w.checkID
		status = StatusCorrelated
		if w.consumed {
			status = StatusDuplicate
		}
		w.consumed = true
	}
	c.mu.Unlock()
	var cid *int64
	if checkID != 0 {
		cid = &checkID
	}
	var id int64
	if err := c.DB.QueryRow(ctx, `INSERT INTO callbacks (received_at, proto, qtype, qname, point, source_ip, raw, token, check_id, asset_id, status, source_matches)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id`,
		ev.At, ev.Proto, ev.QType, ev.QName, p.Point, ev.Source, ev.Raw, p.Token, cid, assetID, status, match).Scan(&id); err != nil {
		return "", true, err
	}
	switch status {
	case StatusCorrelated:
		c.mu.Lock()
		ch := c.waiters[checkID]
		c.mu.Unlock()
		if ch != nil {
			select {
			case ch <- Hit{CallbackID: id, At: ev.At, Proto: ev.Proto, QType: ev.QType, QName: ev.QName, Point: "fichier", Source: ev.Source, SourceMatches: match}:
			default:
			}
		}
	case StatusHoneytoken:
		if c.Log != nil {
			c.Log.Warn("canari fichier lu hors d'un check : compromission probable", "asset", assetID, "source", ev.Source, "nom", ev.QName)
		}
		if c.OnHoneytoken != nil {
			c.OnHoneytoken(assetID, ev)
		}
	}
	return status, true, nil
}

func (c *Correlator) noise(ctx context.Context, ev Event, token string) error {
	if !c.allowNoise() {
		return nil
	}
	_, err := c.DB.Exec(ctx, `INSERT INTO callbacks (received_at, proto, qtype, qname, source_ip, raw, token, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'unknown')`, ev.At, ev.Proto, ev.QType, ev.QName, ev.Source, ev.Raw, token)
	return err
}

func sourceMatches(src string, ips []string) bool {
	a, err := netip.ParseAddr(src)
	if err != nil {
		return false
	}
	for _, s := range ips {
		if b, err := netip.ParseAddr(s); err == nil && b.Unmap() == a.Unmap() {
			return true
		}
	}
	return false
}

// hostOnly retire le port d'une adresse « hôte:port ».
func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
