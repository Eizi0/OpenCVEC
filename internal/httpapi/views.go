package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/Eizi0/OpenCVEC/internal/checks"
)

// Callback est la représentation JSON d'un callback reçu.
type Callback struct {
	ID            int64     `json:"id"`
	ReceivedAt    time.Time `json:"received_at"`
	Proto         string    `json:"proto"`
	QType         string    `json:"qtype"`
	QName         string    `json:"qname"`
	Point         string    `json:"point"`
	SourceIP      string    `json:"source_ip"`
	Raw           string    `json:"raw"`
	Status        string    `json:"status"`
	SourceMatches *bool     `json:"source_matches"`
	CheckID       *int64    `json:"check_id"`
	CampaignID    *int64    `json:"campaign_id"`
	AssetHost     string    `json:"asset_host"`
	Checker       string    `json:"checker"`
}

func (s *Server) queryCallbacks(ctx context.Context, where string, args ...any) ([]Callback, error) {
	rows, err := s.DB.Query(ctx, `SELECT cb.id, cb.received_at, cb.proto, cb.qtype, cb.qname, cb.point, cb.source_ip, cb.raw, cb.status,
		cb.source_matches, cb.check_id, k.campaign_id, COALESCE(a.host, ''), COALESCE(k.checker, '')
		FROM callbacks cb LEFT JOIN checks k ON k.id = cb.check_id LEFT JOIN assets a ON a.id = COALESCE(k.asset_id, cb.asset_id) `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Callback{}
	for rows.Next() {
		var c Callback
		if err := rows.Scan(&c.ID, &c.ReceivedAt, &c.Proto, &c.QType, &c.QName, &c.Point, &c.SourceIP, &c.Raw, &c.Status,
			&c.SourceMatches, &c.CheckID, &c.CampaignID, &c.AssetHost, &c.Checker); err != nil {
			return nil, err
		}
		if ch, ok := checks.Get(c.Checker); ok {
			c.Checker = ch.Info().Name
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Server) listCallbacks(w http.ResponseWriter, r *http.Request, u *User) {
	where := `WHERE true`
	switch r.URL.Query().Get("status") {
	case "correlated":
		where += ` AND cb.status IN ('correlated', 'duplicate')`
	case "rejected":
		where += ` AND cb.status IN ('expired', 'replay', 'unknown')`
	case "selftest":
		where += ` AND cb.status = 'selftest'`
	case "alerts":
		where += ` AND cb.status = 'honeytoken'`
	}
	out, err := s.queryCallbacks(r.Context(), where+` ORDER BY cb.received_at DESC LIMIT 500`)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	var out struct {
		AssetsTotal   int        `json:"assets_total"`
		AssetsOwned   int        `json:"assets_owned"`
		AssetsRenew   int        `json:"assets_renew"`
		Checks30      int        `json:"checks_30d"`
		Fingerprint30 int        `json:"fingerprint_30d"`
		Proved        int        `json:"proved_30d"`
		Probable      int        `json:"probable_30d"`
		Running       int        `json:"running"`
		LastCallback  *time.Time `json:"last_callback"`
		Alerts        []Callback `json:"alerts"`
		Recent        []Check    `json:"recent"`
		Renew         []Asset    `json:"renew"`
	}
	_ = s.DB.QueryRow(ctx, `SELECT count(*),
		count(*) FILTER (WHERE proof_status = 'valid' AND proof_valid_until > now()),
		count(*) FILTER (WHERE proof_status = 'valid' AND proof_valid_until > now() AND proof_valid_until < now() + interval '7 days')
		FROM assets`).Scan(&out.AssetsTotal, &out.AssetsOwned, &out.AssetsRenew)
	var fps []string
	for _, i := range checks.All() {
		if i.Mode == checks.ModeFingerprint {
			fps = append(fps, i.ID)
		}
	}
	_ = s.DB.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE checker = ANY($1)),
		count(*) FILTER (WHERE verdict = 'proved'), count(*) FILTER (WHERE verdict IN ('probable', 'exposed')),
		count(*) FILTER (WHERE status IN ('queued', 'running', 'waiting'))
		FROM checks WHERE created_at > now() - interval '30 days'`, fps).Scan(&out.Checks30, &out.Fingerprint30, &out.Proved, &out.Probable, &out.Running)
	_ = s.DB.QueryRow(ctx, `SELECT max(received_at) FROM callbacks WHERE status <> 'selftest'`).Scan(&out.LastCallback)
	var err error
	if out.Alerts, err = s.queryCallbacks(ctx, `WHERE cb.status = 'honeytoken' AND cb.received_at > now() - interval '30 days' ORDER BY cb.received_at DESC LIMIT 10`); err != nil {
		s.fail(w, r, err)
		return
	}
	if out.Recent, err = s.queryChecks(ctx, `WHERE k.verdict IS NOT NULL ORDER BY k.id DESC LIMIT 8`); err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(ctx, `SELECT `+assetCols+` FROM assets a WHERE a.proof_status <> 'valid' OR a.proof_valid_until < now() + interval '7 days'
		ORDER BY a.proof_valid_until NULLS FIRST LIMIT 6`)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer rows.Close()
	out.Renew = []Asset{}
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		out.Renew = append(out.Renew, a)
	}
	writeJSON(w, http.StatusOK, out)
}
