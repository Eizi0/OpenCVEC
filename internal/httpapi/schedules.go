package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Eizi0/OpenCVEC/internal/checks"
	"github.com/Eizi0/OpenCVEC/internal/notify"
)

type scheduleRow struct {
	ID             int64      `json:"id"`
	AssetID        int64      `json:"asset_id"`
	AssetHost      string     `json:"asset_host"`
	TargetURL      string     `json:"target_url"`
	Checkers       []string   `json:"checkers"`
	EveryDays      int        `json:"every_days"`
	NextRunAt      time.Time  `json:"next_run_at"`
	Enabled        bool       `json:"enabled"`
	CreatedBy      string     `json:"created_by"`
	LastCampaignID *int64     `json:"last_campaign_id"`
	LastRunAt      *time.Time `json:"last_run_at"`
	LastError      string     `json:"last_error"`
}

func (s *Server) listSchedules(w http.ResponseWriter, r *http.Request, u *User) {
	rows, err := s.DB.Query(r.Context(), `SELECT p.id, p.asset_id, a.host, p.target_url, p.checkers, p.every_days, p.next_run_at, p.enabled,
		COALESCE(u.email, ''), p.last_campaign_id, p.last_run_at, p.last_error
		FROM schedules p JOIN assets a ON a.id = p.asset_id LEFT JOIN users u ON u.id = p.created_by ORDER BY p.next_run_at`)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer rows.Close()
	out := []scheduleRow{}
	for rows.Next() {
		var x scheduleRow
		if err := rows.Scan(&x.ID, &x.AssetID, &x.AssetHost, &x.TargetURL, &x.Checkers, &x.EveryDays, &x.NextRunAt, &x.Enabled,
			&x.CreatedBy, &x.LastCampaignID, &x.LastRunAt, &x.LastError); err != nil {
			s.fail(w, r, err)
			return
		}
		out = append(out, x)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createSchedule(w http.ResponseWriter, r *http.Request, u *User) {
	var in struct {
		AssetID   int64    `json:"asset_id"`
		TargetURL string   `json:"target_url"`
		Checkers  []string `json:"checkers"`
		EveryDays int      `json:"every_days"`
		// FirstRunInDays : délai avant la première exécution (0 = à la prochaine minute).
		FirstRunInDays int `json:"first_run_in_days"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.EveryDays < 1 || in.EveryDays > 365 || in.FirstRunInDays < 0 || in.FirstRunInDays > 365 {
		writeErr(w, http.StatusBadRequest, "fréquence : entre 1 et 365 jours")
		return
	}
	a, err := s.loadAsset(r.Context(), in.AssetID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(in.Checkers) == 0 {
		writeErr(w, http.StatusBadRequest, "choisissez au moins un checker")
		return
	}
	for _, id := range in.Checkers {
		if _, ok := checks.Get(id); !ok {
			writeErr(w, http.StatusBadRequest, "checker inconnu : "+id)
			return
		}
	}
	target, err := targetInScope(a, in.TargetURL)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	next := time.Now().Add(time.Duration(in.FirstRunInDays) * 24 * time.Hour)
	var id int64
	if err := s.DB.QueryRow(r.Context(), `INSERT INTO schedules (asset_id, target_url, checkers, every_days, next_run_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`, a.ID, target, in.Checkers, in.EveryDays, next, u.ID).Scan(&id); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, u, "Check programmé", fmt.Sprintf("#%d · %s · tous les %d jours · %v", id, a.Host, in.EveryDays, in.Checkers))
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (s *Server) toggleSchedule(w http.ResponseWriter, r *http.Request, u *User) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "identifiant invalide")
		return
	}
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if _, err := s.DB.Exec(r.Context(), `UPDATE schedules SET enabled = $2 WHERE id = $1`, id, in.Enabled); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, u, "Check programmé", fmt.Sprintf("#%d %s", id, map[bool]string{true: "réactivé", false: "suspendu"}[in.Enabled]))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) deleteSchedule(w http.ResponseWriter, r *http.Request, u *User) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "identifiant invalide")
		return
	}
	tag, err := s.DB.Exec(r.Context(), `DELETE FROM schedules WHERE id = $1`, id)
	if err != nil || tag.RowsAffected() == 0 {
		writeErr(w, http.StatusNotFound, "introuvable")
		return
	}
	s.audit(r, u, "Check programmé", fmt.Sprintf("#%d supprimé", id))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// RunScheduler lance les checks programmés arrivés à échéance, chaque minute.
func (s *Server) RunScheduler(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		s.RunDueSchedules(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunDueSchedules exécute une fois les programmations échues. Chaque lancement passe par les mêmes
// contrôles qu'un lancement manuel (propriété revalidée, périmètre, limites), au nom de son auteur.
func (s *Server) RunDueSchedules(ctx context.Context, now time.Time) {
	rows, err := s.DB.Query(ctx, `SELECT p.id, p.asset_id, a.host, p.target_url, p.checkers, p.every_days, p.created_by
		FROM schedules p JOIN assets a ON a.id = p.asset_id WHERE p.enabled AND p.next_run_at <= $1 ORDER BY p.next_run_at LIMIT 50`, now)
	if err != nil {
		s.Log.Error("programmations", "err", err)
		return
	}
	type due struct {
		id, assetID int64
		host        string
		target      string
		checkers    []string
		every       int
		createdBy   *int64
	}
	var list []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.id, &d.assetID, &d.host, &d.target, &d.checkers, &d.every, &d.createdBy); err == nil {
			list = append(list, d)
		}
	}
	rows.Close()
	for _, d := range list {
		next := now.Add(time.Duration(d.every) * 24 * time.Hour)
		var u *User
		if d.createdBy != nil {
			x := &User{}
			if err := s.DB.QueryRow(ctx, `SELECT id, email, name, role, totp_enabled FROM users WHERE id = $1 AND NOT disabled`, *d.createdBy).
				Scan(&x.ID, &x.Email, &x.Name, &x.Role, &x.TOTPEnabled); err == nil && roleRank[x.Role] >= roleRank[RoleAnalyst] {
				u = x
			}
		}
		var cid int64
		var errMsg string
		if u == nil {
			errMsg = "auteur de la programmation désactivé ou sans droit d'analyste : programmation suspendue"
		} else if id, _, le := s.launch(ctx, nil, u, d.assetID, d.target, d.checkers); le != nil {
			errMsg = le.Error()
		} else {
			cid = id
		}
		var lastCampaign *int64
		if cid != 0 {
			lastCampaign = &cid
		}
		if _, err := s.DB.Exec(ctx, `UPDATE schedules SET next_run_at = $2, last_run_at = $3, last_campaign_id = COALESCE($4, last_campaign_id),
			last_error = $5, enabled = enabled AND $6 WHERE id = $1`, d.id, next, now, lastCampaign, errMsg, u != nil); err != nil {
			s.Log.Error("programmation", "id", d.id, "err", err)
		}
		if errMsg != "" {
			s.audit(nil, nil, "Refus", fmt.Sprintf("check programmé #%d sur %s : %s", d.id, d.host, errMsg))
			if s.Notifier != nil {
				s.Notifier.Send(notify.Event{Kind: notify.KindSchedule, Title: "Check programmé non lancé : " + d.host, Text: errMsg, Link: "/checks"})
			}
		}
	}
}
