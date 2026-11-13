package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/Eizi0/OpenCVEC/internal/checks"
	"github.com/Eizi0/OpenCVEC/internal/report"
)

type reportRow struct {
	ID        int64     `json:"id"`
	Title     string    `json:"title"`
	Summary   string    `json:"summary"`
	Format    string    `json:"format"`
	SHA256    string    `json:"sha256"`
	Size      int       `json:"size"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Server) listReports(w http.ResponseWriter, r *http.Request, u *User) {
	rows, err := s.DB.Query(r.Context(), `SELECT p.id, p.title, p.summary, p.format, p.sha256, length(p.content), COALESCE(u.email, ''), p.created_at
		FROM reports p LEFT JOIN users u ON u.id = p.created_by ORDER BY p.id DESC LIMIT 200`)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer rows.Close()
	out := []reportRow{}
	for rows.Next() {
		var x reportRow
		if err := rows.Scan(&x.ID, &x.Title, &x.Summary, &x.Format, &x.SHA256, &x.Size, &x.CreatedBy, &x.CreatedAt); err != nil {
			s.fail(w, r, err)
			return
		}
		out = append(out, x)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createReport(w http.ResponseWriter, r *http.Request, u *User) {
	var in struct {
		CampaignID          int64  `json:"campaign_id"`
		AssetID             int64  `json:"asset_id"`
		Days                int    `json:"days"`
		Format              string `json:"format"`
		IncludeRaw          bool   `json:"include_raw"`
		IncludeInconclusive bool   `json:"include_inconclusive"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Format != "html" && in.Format != "json" {
		writeErr(w, http.StatusBadRequest, "format : html ou json")
		return
	}
	ctx := r.Context()
	rep := report.Report{GeneratedAt: time.Now(), GeneratedBy: u.Email, CanaryZone: s.Cfg.CanaryZone}
	var where string
	var args []any
	switch {
	case in.CampaignID > 0:
		var host string
		if err := s.DB.QueryRow(ctx, `SELECT a.host FROM campaigns c JOIN assets a ON a.id = c.asset_id WHERE c.id = $1`, in.CampaignID).Scan(&host); err != nil {
			s.fail(w, r, err)
			return
		}
		rep.Title = fmt.Sprintf("Campagne #%d · %s", in.CampaignID, host)
		rep.Scope = fmt.Sprintf("campagne #%d", in.CampaignID)
		where, args = `WHERE k.campaign_id = $1`, []any{in.CampaignID}
	case in.AssetID > 0:
		var host string
		if err := s.DB.QueryRow(ctx, `SELECT host FROM assets WHERE id = $1`, in.AssetID).Scan(&host); err != nil {
			s.fail(w, r, err)
			return
		}
		days := in.Days
		if days <= 0 {
			days = 30
		}
		rep.Title = fmt.Sprintf("%s · %d derniers jours", host, days)
		rep.Scope = rep.Title
		where, args = `WHERE k.asset_id = $1 AND k.created_at > $2`, []any{in.AssetID, time.Now().Add(-time.Duration(days) * 24 * time.Hour)}
	default:
		days := in.Days
		if days <= 0 {
			days = 30
		}
		rep.Title = fmt.Sprintf("Revue de tous les assets · %d derniers jours", days)
		rep.Scope = rep.Title
		where, args = `WHERE k.created_at > $1`, []any{time.Now().Add(-time.Duration(days) * 24 * time.Hour)}
	}
	where += ` AND k.verdict IS NOT NULL`
	if !in.IncludeInconclusive {
		where += ` AND k.verdict NOT IN ('inconclusive', 'error')`
	}
	list, err := s.queryChecks(ctx, where+` ORDER BY k.id`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, c := range list {
		it := report.Item{CheckID: c.ID, CampaignID: c.CampaignID, Asset: c.AssetHost, TargetURL: c.TargetURL, Checker: c.CheckerName,
			CVEs: c.CVEs, Mode: c.Mode, Verdict: c.Verdict, Summary: c.Summary, SentAt: c.SentAt, FinishedAt: c.FinishedAt}
		if ch, ok := checks.Get(c.Checker); ok {
			i := ch.Info()
			it.Sent, it.Remediation = i.Sent, i.Remediation
		}
		var d struct {
			Canary   string            `json:"canary"`
			Evidence map[string]string `json:"evidence"`
		}
		_ = json.Unmarshal(c.Detail, &d)
		it.Canary, it.Evidence = d.Canary, d.Evidence
		cbs, err := s.queryCallbacks(ctx, `WHERE cb.check_id = $1 ORDER BY cb.received_at`, c.ID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		for _, cb := range cbs {
			x := report.Callback{ReceivedAt: cb.ReceivedAt, Proto: cb.Proto, QType: cb.QType, QName: cb.QName, Point: cb.Point,
				SourceIP: cb.SourceIP, Status: cb.Status, SourceMatches: cb.SourceMatches != nil && *cb.SourceMatches}
			if in.IncludeRaw {
				x.Raw = cb.Raw
			}
			it.Callbacks = append(it.Callbacks, x)
		}
		rep.Items = append(rep.Items, it)
	}
	rep.Count()
	var content []byte
	if in.Format == "json" {
		content, err = rep.JSON()
	} else {
		content, err = rep.HTML()
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sum := sha256.Sum256(content)
	hexsum := hex.EncodeToString(sum[:])
	var id int64
	if err := s.DB.QueryRow(ctx, `INSERT INTO reports (title, summary, format, content, sha256, created_by) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		rep.Title, rep.Counts.Summary(), in.Format, content, hexsum, u.ID).Scan(&id); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, u, "Rapport généré", fmt.Sprintf("%s · %s · sha256 %s", rep.Title, in.Format, hexsum[:12]))
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "sha256": hexsum})
}

func (s *Server) downloadReport(w http.ResponseWriter, r *http.Request, u *User) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "identifiant invalide")
		return
	}
	var format, sum string
	var content []byte
	if err := s.DB.QueryRow(r.Context(), `SELECT format, content, sha256 FROM reports WHERE id = $1`, id).Scan(&format, &content, &sum); err != nil {
		s.fail(w, r, err)
		return
	}
	name := "opencvec-rapport-" + strconv.FormatInt(id, 10) + "." + format
	if format == "json" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Le rapport est une page autonome : la CSP de l'application est remplacée par une CSP sans script.
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:")
	}
	disp := "inline"
	if r.URL.Query().Get("download") == "1" {
		disp = "attachment"
	}
	w.Header().Set("Content-Disposition", disp+`; filename="`+name+`"`)
	w.Header().Set("X-Content-SHA256", sum)
	_, _ = w.Write(content)
}
