package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"

	"github.com/jackc/pgx/v5"
)

// Preinstall installe ou met à jour les plugins officiels embarqués dans le binaire.
//   - Un plugin absent est installé, sauf si un administrateur l'a désinstallé volontairement.
//   - Un plugin officiel déjà installé est mis à jour si la version embarquée est plus récente.
//   - Un plugin du même identifiant installé depuis une autre source n'est jamais remplacé.
//
// Chaque fichier est vérifié avec la clé officielle : un binaire modifié ne peut pas faire
// passer un plugin altéré pour officiel.
func (s *Store) Preinstall(ctx context.Context, files fs.FS) (installed []string, err error) {
	pub, err := ParsePublicKey(s.Official)
	if err != nil {
		return nil, fmt.Errorf("clé officielle : %w", err)
	}
	trusted := []Publisher{{Name: OfficialName, Key: pub}}
	removed, err := s.removed(ctx)
	if err != nil {
		return nil, err
	}
	names, err := fs.Glob(files, "*.yaml")
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		data, err := fs.ReadFile(files, name)
		if err != nil {
			return installed, err
		}
		sig, _ := fs.ReadFile(files, name+".sig")
		p, err := Parse(data)
		if err != nil {
			return installed, fmt.Errorf("plugin officiel %s : %w", name, err)
		}
		if _, err := Verify(data, string(sig), trusted); err != nil {
			return installed, fmt.Errorf("plugin officiel %s : %w", name, err)
		}
		if removed[p.ID] {
			continue
		}
		var curVersion, curPublisher string
		err = s.DB.QueryRow(ctx, `SELECT version, publisher FROM plugins WHERE id = $1`, p.ID).Scan(&curVersion, &curPublisher)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return installed, err
		case curPublisher != OfficialName:
			continue
		default:
			cv, _ := parseVersion(curVersion)
			nv, _ := parseVersion(p.Version)
			if cmp(nv, cv) <= 0 {
				continue
			}
		}
		if _, err := s.Install(ctx, data, string(sig), "préinstallé ("+path.Base(name)+")", 0, false); err != nil {
			return installed, fmt.Errorf("plugin officiel %s : %w", name, err)
		}
		installed = append(installed, p.ID+" "+p.Version)
	}
	return installed, nil
}

// removed renvoie les plugins officiels qu'un administrateur a désinstallés.
func (s *Store) removed(ctx context.Context) (map[string]bool, error) {
	out := map[string]bool{}
	var raw []byte
	err := s.DB.QueryRow(ctx, `SELECT value FROM settings WHERE key = 'removed_plugins'`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	_ = json.Unmarshal(raw, &ids)
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}

func (s *Store) setRemoved(ctx context.Context, id string, on bool) error {
	m, err := s.removed(ctx)
	if err != nil {
		return err
	}
	if on {
		m[id] = true
	} else {
		delete(m, id)
	}
	ids := make([]string, 0, len(m))
	for k := range m {
		ids = append(ids, k)
	}
	b, _ := json.Marshal(ids)
	_, err = s.DB.Exec(ctx, `INSERT INTO settings (key, value) VALUES ('removed_plugins', $1)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, b)
	return err
}
