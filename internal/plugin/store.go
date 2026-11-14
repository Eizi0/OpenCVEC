package plugin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Eizi0/OpenCVEC/internal/checks"
)

// OfficialName est le nom de l'éditeur officiel.
const OfficialName = "OpenCVEC (officiel)"

// Store gère les plugins installés et les éditeurs de confiance.
type Store struct {
	DB  *pgxpool.Pool
	Log *slog.Logger
	// Official est la clé publique de l'éditeur officiel, enregistrée au démarrage.
	Official string
}

// EnsureOfficial enregistre l'éditeur officiel s'il est absent.
func (s *Store) EnsureOfficial(ctx context.Context) error {
	if s.Official == "" {
		return nil
	}
	pub, err := ParsePublicKey(s.Official)
	if err != nil {
		return fmt.Errorf("clé officielle : %w", err)
	}
	_, err = s.DB.Exec(ctx, `INSERT INTO publishers (name, public_key, key_id, builtin) VALUES ($1, $2, $3, true)
		ON CONFLICT (public_key) DO NOTHING`, OfficialName, strings.TrimSpace(s.Official), KeyID(pub))
	return err
}

// Trusted renvoie les éditeurs de confiance.
func (s *Store) Trusted(ctx context.Context) ([]Publisher, error) {
	rows, err := s.DB.Query(ctx, `SELECT name, public_key FROM publishers ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Publisher
	for rows.Next() {
		var name, key string
		if err := rows.Scan(&name, &key); err != nil {
			return nil, err
		}
		if pub, err := ParsePublicKey(key); err == nil {
			out = append(out, Publisher{Name: name, Key: pub})
		}
	}
	return out, rows.Err()
}

// Check est le résultat de l'analyse d'un plugin avant installation.
type Check struct {
	Plugin    *Plugin
	SHA256    string
	Signed    bool
	Publisher string
	SigError  string
}

// Inspect analyse un plugin et sa signature sans l'installer.
func (s *Store) Inspect(ctx context.Context, data []byte, sig string) (Check, error) {
	p, err := Parse(data)
	if err != nil {
		return Check{}, err
	}
	if checks.IsBuiltin(p.ID) {
		return Check{}, fmt.Errorf("l'identifiant %q est réservé par un checker intégré", p.ID)
	}
	trusted, err := s.Trusted(ctx)
	if err != nil {
		return Check{}, err
	}
	c := Check{Plugin: p, SHA256: SHA256(data)}
	pub, err := Verify(data, sig, trusted)
	if err != nil {
		c.SigError = err.Error()
	} else {
		c.Signed, c.Publisher = true, pub.Name
	}
	return c, nil
}

// ErrUntrusted est renvoyée quand un plugin non signé est refusé.
var ErrUntrusted = errors.New("plugin refusé : signature absente ou invalide (activez le mode développeur pour installer un plugin non signé)")

// Install analyse, vérifie et enregistre un plugin, puis l'active.
func (s *Store) Install(ctx context.Context, data []byte, sig, source string, userID int64, allowUnsigned bool) (Check, error) {
	c, err := s.Inspect(ctx, data, sig)
	if err != nil {
		return c, err
	}
	if !c.Signed && !allowUnsigned {
		return c, fmt.Errorf("%w : %s", ErrUntrusted, c.SigError)
	}
	_, err = s.DB.Exec(ctx, `INSERT INTO plugins (id, version, name, content, signature, sha256, publisher, signed, enabled, source, installed_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true, $9, $10)
		ON CONFLICT (id) DO UPDATE SET version = EXCLUDED.version, name = EXCLUDED.name, content = EXCLUDED.content,
			signature = EXCLUDED.signature, sha256 = EXCLUDED.sha256, publisher = EXCLUDED.publisher, signed = EXCLUDED.signed,
			enabled = true, source = EXCLUDED.source, installed_by = EXCLUDED.installed_by, installed_at = now()`,
		c.Plugin.ID, c.Plugin.Version, c.Plugin.Name, data, strings.TrimSpace(sig), c.SHA256, c.Publisher, c.Signed, source, nullID(userID))
	if err != nil {
		return c, err
	}
	if userID != 0 {
		// Une installation manuelle annule une désinstallation volontaire antérieure.
		if err := s.setRemoved(ctx, c.Plugin.ID, false); err != nil {
			return c, err
		}
	}
	return c, checks.Register(&Checker{P: c.Plugin, Publisher: c.Publisher, Signed: c.Signed})
}

// SetEnabled active ou désactive un plugin installé.
func (s *Store) SetEnabled(ctx context.Context, id string, on, allowUnsigned bool) error {
	if !on {
		if _, err := s.DB.Exec(ctx, `UPDATE plugins SET enabled = false WHERE id = $1`, id); err != nil {
			return err
		}
		checks.Unregister(id)
		return nil
	}
	if _, err := s.DB.Exec(ctx, `UPDATE plugins SET enabled = true WHERE id = $1`, id); err != nil {
		return err
	}
	return s.Load(ctx, allowUnsigned)
}

// Remove désinstalle un plugin.
func (s *Store) Remove(ctx context.Context, id string) error {
	tag, err := s.DB.Exec(ctx, `DELETE FROM plugins WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	checks.Unregister(id)
	// Retenu pour que la préinstallation ne le réinstalle pas au prochain démarrage.
	return s.setRemoved(ctx, id, true)
}

func nullID(id int64) *int64 {
	if id == 0 {
		return nil
	}
	return &id
}

// Load (re)charge tous les plugins actifs. La signature est revérifiée à chaque chargement :
// un éditeur retiré des éditeurs de confiance désactive de fait ses plugins.
func (s *Store) Load(ctx context.Context, allowUnsigned bool) error {
	trusted, err := s.Trusted(ctx)
	if err != nil {
		return err
	}
	rows, err := s.DB.Query(ctx, `SELECT id, content, signature, enabled FROM plugins`)
	if err != nil {
		return err
	}
	type row struct {
		id      string
		content []byte
		sig     string
		enabled bool
	}
	var list []row
	for rows.Next() {
		var x row
		if err := rows.Scan(&x.id, &x.content, &x.sig, &x.enabled); err != nil {
			rows.Close()
			return err
		}
		list = append(list, x)
	}
	rows.Close()
	for _, x := range list {
		checks.Unregister(x.id)
		if !x.enabled {
			continue
		}
		p, err := Parse(x.content)
		if err != nil {
			s.Log.Error("plugin illisible ignoré", "plugin", x.id, "err", err)
			continue
		}
		pub, verr := Verify(x.content, x.sig, trusted)
		signed := verr == nil
		if !signed && !allowUnsigned {
			s.Log.Warn("plugin non chargé : signature absente ou éditeur non approuvé", "plugin", x.id, "err", verr)
			_, _ = s.DB.Exec(ctx, `UPDATE plugins SET signed = false WHERE id = $1`, x.id)
			continue
		}
		_, _ = s.DB.Exec(ctx, `UPDATE plugins SET signed = $2, publisher = $3 WHERE id = $1`, x.id, signed, pub.Name)
		if err := checks.Register(&Checker{P: p, Publisher: pub.Name, Signed: signed}); err != nil {
			s.Log.Error("plugin non chargé", "plugin", x.id, "err", err)
		}
	}
	return nil
}
