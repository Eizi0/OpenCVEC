// Package settings lit et écrit les réglages modifiables depuis l'interface.
package settings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// General regroupe les réglages des checks.
type General struct {
	CanaryTTLMinutes  int `json:"canary_ttl_minutes"`
	WaitSeconds       int `json:"wait_seconds"`
	ChecksPerAssetDay int `json:"checks_per_asset_day"`
	ChecksPerUserHour int `json:"checks_per_user_hour"`
	// AllowUnsignedPlugins (mode développeur) autorise les plugins non signés.
	AllowUnsignedPlugins bool `json:"allow_unsigned_plugins"`
	// RetentionDays : durée de conservation du bruit du récepteur et des rapports (0 = illimitée).
	RetentionDays int `json:"retention_days"`
}

// Defaults sont les valeurs initiales.
var Defaults = General{CanaryTTLMinutes: 15, WaitSeconds: 120, ChecksPerAssetDay: 10, ChecksPerUserHour: 60, RetentionDays: 180}

// Validate borne les valeurs.
func (g General) Validate() error {
	switch {
	case g.CanaryTTLMinutes < 5 || g.CanaryTTLMinutes > 60:
		return errors.New("durée de vie du canari : entre 5 et 60 minutes")
	case g.WaitSeconds < 15 || g.WaitSeconds > 600:
		return errors.New("attente du callback : entre 15 et 600 secondes")
	case g.WaitSeconds > g.CanaryTTLMinutes*60:
		return errors.New("l'attente du callback ne peut pas dépasser la durée de vie du canari")
	case g.ChecksPerAssetDay < 1 || g.ChecksPerAssetDay > 500:
		return errors.New("checks par asset et par jour : entre 1 et 500")
	case g.ChecksPerUserHour < 1 || g.ChecksPerUserHour > 1000:
		return errors.New("checks par utilisateur et par heure : entre 1 et 1000")
	case g.RetentionDays != 0 && (g.RetentionDays < 7 || g.RetentionDays > 3650):
		return errors.New("conservation : 0 (illimitée) ou entre 7 et 3650 jours")
	}
	return nil
}

// Load lit les réglages (valeurs par défaut si absents).
func Load(ctx context.Context, db *pgxpool.Pool) (General, error) {
	g := Defaults
	var raw []byte
	err := db.QueryRow(ctx, `SELECT value FROM settings WHERE key = 'general'`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return g, nil
	}
	if err != nil {
		return g, err
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		return Defaults, fmt.Errorf("réglages illisibles : %w", err)
	}
	return g, nil
}

// Save enregistre les réglages.
func Save(ctx context.Context, db *pgxpool.Pool, g General) error {
	if err := g.Validate(); err != nil {
		return err
	}
	b, _ := json.Marshal(g)
	_, err := db.Exec(ctx, `INSERT INTO settings (key, value) VALUES ('general', $1)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, b)
	return err
}

// Allowlist renvoie les plages autorisées dont la revue n'est pas dépassée.
func Allowlist(ctx context.Context, db *pgxpool.Pool) ([]netip.Prefix, error) {
	rows, err := db.Query(ctx, `SELECT cidr::text FROM allowlist WHERE review_at > $1`, time.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []netip.Prefix
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out, rows.Err()
}
