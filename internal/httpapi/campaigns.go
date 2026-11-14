package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/Eizi0/OpenCVEC/internal/checks"
	"github.com/Eizi0/OpenCVEC/internal/settings"
)

func (s *Server) listCheckers(w http.ResponseWriter, r *http.Request, u *User) {
	writeJSON(w, http.StatusOK, checks.All())
}

// Check est la représentation JSON d'un check.
type Check struct {
	ID          int64           `json:"id"`
	CampaignID  int64           `json:"campaign_id"`
	AssetID     int64           `json:"asset_id"`
	AssetHost   string          `json:"asset_host"`
	TargetURL   string          `json:"target_url"`
	Checker     string          `json:"checker"`
	CheckerName string          `json:"checker_name"`
	CVEs        []string        `json:"cves"`
	Mode        string          `json:"mode"`
	Status      string          `json:"status"`
	Verdict     string          `json:"verdict"`
	Summary     string          `json:"summary"`
	Detail      json.RawMessage `json:"detail"`
	CreatedAt   time.Time       `json:"created_at"`
	StartedAt   *time.Time      `json:"started_at"`
	SentAt      *time.Time      `json:"sent_at"`
	FinishedAt  *time.Time      `json:"finished_at"`
}

const checkCols = `k.id, k.campaign_id, k.asset_id, a.host, c.target_url, k.checker, k.status, COALESCE(k.verdict, ''), k.summary, k.detail,
	k.created_at, k.started_at, k.sent_at, k.finished_at`
const checkFrom = ` FROM checks k JOIN assets a ON a.id = k.asset_id JOIN campaigns c ON c.id = k.campaign_id`

func scanCheck(row scanner) (Check, error) {
	var c Check
	var detail []byte
	err := row.Scan(&c.ID, &c.CampaignID, &c.AssetID, &c.AssetHost, &c.TargetURL, &c.Checker, &c.Status, &c.Verdict, &c.Summary, &detail,
		&c.CreatedAt, &c.StartedAt, &c.SentAt, &c.FinishedAt)
	if err != nil {
		return c, err
	}
	c.Detail = detail
	if ch, ok := checks.Get(c.Checker); ok {
		i := ch.Info()
		c.CheckerName, c.CVEs, c.Mode = i.Name, i.CVEs, i.Mode
	} else {
		c.CheckerName, c.CVEs = c.Checker, []string{}
	}
	return c, nil
}

func (s *Server) queryChecks(ctx context.Context, where string, args ...any) ([]Check, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+checkCols+checkFrom+` `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Check{}
	for rows.Next() {
		c, err := scanCheck(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// targetInScope vérifie que l'URL cible désigne bien l'asset prouvé.
func targetInScope(a Asset, raw string) (string, error) {
	if raw == "" {
		if a.DefaultURL == "" {
			return "", fmt.Errorf("pour une plage, indiquez l'URL d'une machine de la plage")
		}
		return a.DefaultURL, nil
	}
	if len(raw) > 2000 {
		return "", fmt.Errorf("URL trop longue")
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("URL cible invalide : http(s)://hôte[:port]/chemin")
	}
	if u.User != nil {
		return "", fmt.Errorf("les identifiants dans l'URL ne sont pas acceptés")
	}
	u.Fragment = ""
	h := strings.ToLower(u.Hostname())
	switch a.Kind {
	case "domain":
		if h != a.Host {
			return "", fmt.Errorf("l'URL doit viser %s (asset prouvé), pas %s", a.Host, h)
		}
	case "ip":
		ip, err := netip.ParseAddr(h)
		if err != nil || ip.Unmap().String() != a.Host {
			return "", fmt.Errorf("l'URL doit viser l'adresse %s", a.Host)
		}
	case "cidr":
		p, _ := netip.ParsePrefix(a.Host)
		ip, err := netip.ParseAddr(h)
		if err != nil || !p.Contains(ip.Unmap()) {
			return "", fmt.Errorf("l'URL doit viser une adresse IP de la plage %s", a.Host)
		}
	}
	return u.String(), nil
}

func (s *Server) createCampaign(w http.ResponseWriter, r *http.Request, u *User) {
	// Seuls ces champs sont acceptés : tout champ inconnu (payload, URL de callback…) est refusé.
	var in struct {
		AssetID   int64    `json:"asset_id"`
		TargetURL string   `json:"target_url"`
		Checkers  []string `json:"checkers"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	cid, proofDetail, le := s.launch(r.Context(), r, u, in.AssetID, in.TargetURL, in.Checkers)
	if le != nil {
		if le.err != nil {
			s.fail(w, r, le.err)
		} else {
			writeErr(w, le.status, le.msg)
		}
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": cid, "proof": proofDetail})
}

// launchErr est une erreur de lancement : refus (statut et message) ou erreur interne.
type launchErr struct {
	status int
	msg    string
	err    error
}

func (e *launchErr) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return e.msg
}

// launch applique tous les contrôles (périmètre, limites, revalidation de la propriété) puis crée
// et met en file une campagne. r peut être nil (check programmé) : l'audit n'a alors pas d'IP.
func (s *Server) launch(ctx context.Context, r *http.Request, u *User, assetID int64, targetURL string, checkerIDs []string) (int64, string, *launchErr) {
	a, err := s.loadAsset(ctx, assetID)
	if err != nil {
		return 0, "", &launchErr{err: err}
	}
	var ids []string
	seen := map[string]bool{}
	for _, id := range checkerIDs {
		if _, ok := checks.Get(id); !ok {
			return 0, "", &launchErr{status: http.StatusBadRequest, msg: "checker inconnu : " + id}
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return 0, "", &launchErr{status: http.StatusBadRequest, msg: "choisissez au moins un checker"}
	}
	target, err := targetInScope(a, targetURL)
	if err != nil {
		s.audit(r, u, "Refus", fmt.Sprintf("%s · cible hors périmètre : %s", a.Host, err))
		return 0, "", &launchErr{status: http.StatusBadRequest, msg: err.Error()}
	}
	st, err := settings.Load(ctx, s.DB)
	if err != nil {
		return 0, "", &launchErr{err: err}
	}
	var perAsset, perUser int
	_ = s.DB.QueryRow(ctx, `SELECT count(*) FROM checks WHERE asset_id = $1 AND created_at > now() - interval '24 hours'`, a.ID).Scan(&perAsset)
	_ = s.DB.QueryRow(ctx, `SELECT count(*) FROM checks k JOIN campaigns c ON c.id = k.campaign_id
		WHERE c.created_by = $1 AND k.created_at > now() - interval '1 hour'`, u.ID).Scan(&perUser)
	if perAsset+len(ids) > st.ChecksPerAssetDay {
		s.audit(r, u, "Refus", fmt.Sprintf("limite de débit atteinte · %s (%d/%d sur 24 h)", a.Host, perAsset, st.ChecksPerAssetDay))
		return 0, "", &launchErr{status: http.StatusTooManyRequests, msg: fmt.Sprintf("limite atteinte pour cet asset : %d checks sur 24 h (déjà %d)", st.ChecksPerAssetDay, perAsset)}
	}
	if perUser+len(ids) > st.ChecksPerUserHour {
		s.audit(r, u, "Refus", fmt.Sprintf("limite de débit utilisateur atteinte (%d/%d sur 1 h)", perUser, st.ChecksPerUserHour))
		return 0, "", &launchErr{status: http.StatusTooManyRequests, msg: fmt.Sprintf("limite atteinte : %d checks par heure et par utilisateur", st.ChecksPerUserHour)}
	}
	// Revalidation de la propriété juste avant l'envoi.
	if !a.Owned {
		s.audit(r, u, "Refus", fmt.Sprintf("%s · propriété non prouvée, check bloqué", a.Host))
		return 0, "", &launchErr{status: http.StatusForbidden, msg: "propriété de l'asset non prouvée : aucun check possible"}
	}
	res, err := s.revalidate(ctx, a)
	if err != nil {
		return 0, "", &launchErr{err: err}
	}
	if !res.OK {
		s.audit(r, u, "Refus", fmt.Sprintf("%s · revalidation de la propriété échouée : %s", a.Host, res.Detail))
		return 0, "", &launchErr{status: http.StatusForbidden, msg: "la revalidation de la propriété a échoué : " + res.Detail}
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return 0, "", &launchErr{err: err}
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var cid int64
	if err := tx.QueryRow(ctx, `INSERT INTO campaigns (asset_id, target_url, created_by) VALUES ($1, $2, $3) RETURNING id`, a.ID, target, u.ID).Scan(&cid); err != nil {
		return 0, "", &launchErr{err: err}
	}
	var checkIDs []int64
	for _, id := range ids {
		var kid int64
		if err := tx.QueryRow(ctx, `INSERT INTO checks (campaign_id, asset_id, checker) VALUES ($1, $2, $3) RETURNING id`, cid, a.ID, id).Scan(&kid); err != nil {
			return 0, "", &launchErr{err: err}
		}
		checkIDs = append(checkIDs, kid)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, "", &launchErr{err: err}
	}
	s.audit(r, u, "Check lancé", fmt.Sprintf("campagne #%d · %s · %s · %s", cid, a.Host, target, strings.Join(ids, ", ")))
	for _, id := range checkIDs {
		s.Runner.Enqueue(id)
	}
	return cid, res.Detail, nil
}

// Campaign est la représentation JSON d'une campagne.
type Campaign struct {
	ID        int64      `json:"id"`
	AssetID   int64      `json:"asset_id"`
	AssetHost string     `json:"asset_host"`
	TargetURL string     `json:"target_url"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	Cancelled bool       `json:"cancelled"`
	Total     int        `json:"total"`
	Pending   int        `json:"pending"`
	Proved    int        `json:"proved"`
	Probable  int        `json:"probable"`
	Checks    []Check    `json:"checks,omitempty"`
	Events    []Callback `json:"events,omitempty"`
}

const campaignSelect = `SELECT c.id, c.asset_id, a.host, c.target_url, COALESCE(u.email, ''), c.created_at, c.cancelled,
	(SELECT count(*) FROM checks k WHERE k.campaign_id = c.id),
	(SELECT count(*) FROM checks k WHERE k.campaign_id = c.id AND k.status IN ('queued', 'running', 'waiting')),
	(SELECT count(*) FROM checks k WHERE k.campaign_id = c.id AND k.verdict = 'proved'),
	(SELECT count(*) FROM checks k WHERE k.campaign_id = c.id AND k.verdict IN ('probable', 'exposed'))
	FROM campaigns c JOIN assets a ON a.id = c.asset_id LEFT JOIN users u ON u.id = c.created_by`

func scanCampaign(row scanner) (Campaign, error) {
	var c Campaign
	err := row.Scan(&c.ID, &c.AssetID, &c.AssetHost, &c.TargetURL, &c.CreatedBy, &c.CreatedAt, &c.Cancelled, &c.Total, &c.Pending, &c.Proved, &c.Probable)
	return c, err
}

func (s *Server) listCampaigns(w http.ResponseWriter, r *http.Request, u *User) {
	rows, err := s.DB.Query(r.Context(), campaignSelect+` ORDER BY c.id DESC LIMIT 200`)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer rows.Close()
	out := []Campaign{}
	for rows.Next() {
		c, err := scanCampaign(rows)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		out = append(out, c)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getCampaign(w http.ResponseWriter, r *http.Request, u *User) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "identifiant invalide")
		return
	}
	ctx := r.Context()
	c, err := scanCampaign(s.DB.QueryRow(ctx, campaignSelect+` WHERE c.id = $1`, id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if c.Checks, err = s.queryChecks(ctx, `WHERE k.campaign_id = $1 ORDER BY k.id`, id); err != nil {
		s.fail(w, r, err)
		return
	}
	if c.Events, err = s.queryCallbacks(ctx, `WHERE k.campaign_id = $1 ORDER BY cb.received_at DESC LIMIT 100`, id); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) cancelCampaign(w http.ResponseWriter, r *http.Request, u *User) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "identifiant invalide")
		return
	}
	if _, err := s.DB.Exec(r.Context(), `UPDATE campaigns SET cancelled = true WHERE id = $1`, id); err != nil {
		s.fail(w, r, err)
		return
	}
	_, _ = s.DB.Exec(r.Context(), `UPDATE checks SET status = 'cancelled', finished_at = now(), summary = 'Campagne annulée avant l''exécution.'
		WHERE campaign_id = $1 AND status = 'queued'`, id)
	s.audit(r, u, "Campagne annulée", fmt.Sprintf("campagne #%d", id))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// CheckDetail regroupe un check, la fiche de son checker et ses callbacks.
type CheckDetail struct {
	Check
	Info      checks.Info `json:"info"`
	Callbacks []Callback  `json:"callbacks"`
}

func (s *Server) getCheck(w http.ResponseWriter, r *http.Request, u *User) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "identifiant invalide")
		return
	}
	ctx := r.Context()
	c, err := scanCheck(s.DB.QueryRow(ctx, `SELECT `+checkCols+checkFrom+` WHERE k.id = $1`, id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := CheckDetail{Check: c}
	if ch, ok := checks.Get(c.Checker); ok {
		out.Info = ch.Info()
	}
	if out.Callbacks, err = s.queryCallbacks(ctx, `WHERE cb.check_id = $1 ORDER BY cb.received_at`, id); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
