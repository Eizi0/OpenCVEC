package httpapi

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Eizi0/OpenCVEC/internal/auth"
)

const tokenPrefix = "ocv_"

// bearer renvoie le jeton d'API de l'en-tête Authorization, s'il y en a un.
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer "+tokenPrefix) {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

// tokenUser authentifie un jeton d'API (le rôle est celui de son propriétaire).
func (s *Server) tokenUser(r *http.Request, tok string) (*User, bool) {
	u := &User{}
	var id int64
	err := s.DB.QueryRow(r.Context(), `SELECT t.id, u.id, u.email, u.name, u.role, u.totp_enabled FROM api_tokens t
		JOIN users u ON u.id = t.user_id
		WHERE t.token_hash = $1 AND (t.expires_at IS NULL OR t.expires_at > now()) AND NOT u.disabled`,
		auth.HashToken(tok)).Scan(&id, &u.ID, &u.Email, &u.Name, &u.Role, &u.TOTPEnabled)
	if err != nil {
		return nil, false
	}
	_, _ = s.DB.Exec(r.Context(), `UPDATE api_tokens SET last_used_at = now() WHERE id = $1`, id)
	return u, true
}

type tokenRow struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
}

// Les jetons se gèrent uniquement depuis une session : un jeton ne peut pas en créer d'autres.
func sessionOnly(w http.ResponseWriter, r *http.Request) bool {
	if bearer(r) != "" {
		writeErr(w, http.StatusForbidden, "les jetons d'API se gèrent depuis l'interface, pas avec un jeton")
		return false
	}
	return true
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request, u *User) {
	rows, err := s.DB.Query(r.Context(), `SELECT id, name, prefix, created_at, last_used_at, expires_at FROM api_tokens WHERE user_id = $1 ORDER BY id`, u.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer rows.Close()
	out := []tokenRow{}
	for rows.Next() {
		var t tokenRow
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &t.CreatedAt, &t.LastUsedAt, &t.ExpiresAt); err != nil {
			s.fail(w, r, err)
			return
		}
		out = append(out, t)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request, u *User) {
	if !sessionOnly(w, r) {
		return
	}
	var in struct {
		Name        string `json:"name"`
		ExpiresDays int    `json:"expires_days"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	name := strings.TrimSpace(in.Name)
	if len(name) < 2 || len(name) > 60 {
		writeErr(w, http.StatusBadRequest, "nom du jeton : 2 à 60 caractères")
		return
	}
	if in.ExpiresDays < 0 || in.ExpiresDays > 730 {
		writeErr(w, http.StatusBadRequest, "expiration : 0 (jamais) à 730 jours")
		return
	}
	var exp *time.Time
	if in.ExpiresDays > 0 {
		t := time.Now().Add(time.Duration(in.ExpiresDays) * 24 * time.Hour)
		exp = &t
	}
	tok := tokenPrefix + auth.NewToken()
	if _, err := s.DB.Exec(r.Context(), `INSERT INTO api_tokens (user_id, name, token_hash, prefix, expires_at) VALUES ($1, $2, $3, $4, $5)`,
		u.ID, name, auth.HashToken(tok), tok[:10], exp); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, u, "Jeton d'API créé", fmt.Sprintf("%s (%s…)", name, tok[:10]))
	writeJSON(w, http.StatusCreated, map[string]string{"token": tok})
}

func (s *Server) deleteToken(w http.ResponseWriter, r *http.Request, u *User) {
	if !sessionOnly(w, r) {
		return
	}
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "identifiant invalide")
		return
	}
	var name string
	if err := s.DB.QueryRow(r.Context(), `DELETE FROM api_tokens WHERE id = $1 AND user_id = $2 RETURNING name`, id, u.ID).Scan(&name); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, u, "Jeton d'API révoqué", name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
