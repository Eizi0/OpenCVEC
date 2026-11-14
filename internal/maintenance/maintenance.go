// Package maintenance purge régulièrement les données devenues inutiles.
//
// Sont purgés après la durée de conservation : le bruit du récepteur (jetons inconnus, auto-tests,
// canaris expirés, rejeux, doublons) et les rapports générés. Les preuves (callbacks corrélés),
// les alertes de jeton piège, les checks et le journal d'audit ne sont jamais purgés.
package maintenance

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Eizi0/OpenCVEC/internal/settings"
)

// Result compte les lignes supprimées.
type Result struct {
	Callbacks, Reports, Sessions int64
}

// Purge applique la politique de conservation une fois.
func Purge(ctx context.Context, db *pgxpool.Pool, now time.Time) (Result, error) {
	var r Result
	// Sessions, défis TOTP et compteurs expirés : toujours.
	for _, q := range []string{
		`DELETE FROM sessions WHERE expires_at < $1`,
		`DELETE FROM mfa_challenges WHERE expires_at < $1`,
		`DELETE FROM rate_limits WHERE reset_at < $1`,
	} {
		tag, err := db.Exec(ctx, q, now)
		if err != nil {
			return r, err
		}
		r.Sessions += tag.RowsAffected()
	}
	st, err := settings.Load(ctx, db)
	if err != nil {
		return r, err
	}
	if st.RetentionDays <= 0 {
		return r, nil
	}
	limit := now.Add(-time.Duration(st.RetentionDays) * 24 * time.Hour)
	tag, err := db.Exec(ctx, `DELETE FROM callbacks WHERE received_at < $1
		AND status IN ('unknown', 'selftest', 'expired', 'replay', 'duplicate')`, limit)
	if err != nil {
		return r, err
	}
	r.Callbacks = tag.RowsAffected()
	tag, err = db.Exec(ctx, `DELETE FROM reports WHERE created_at < $1`, limit)
	if err != nil {
		return r, err
	}
	r.Reports = tag.RowsAffected()
	return r, nil
}

// Run purge toutes les heures jusqu'à l'annulation du contexte.
func Run(ctx context.Context, db *pgxpool.Pool, log *slog.Logger) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		r, err := Purge(ctx, db, time.Now())
		if err != nil {
			log.Error("purge", "err", err)
		} else if r.Callbacks+r.Reports > 0 {
			log.Info("purge des données anciennes", "callbacks", r.Callbacks, "rapports", r.Reports)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
