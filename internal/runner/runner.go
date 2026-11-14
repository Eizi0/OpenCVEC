// Package runner exécute les checks : émission du canari, envoi du payload figé, attente du
// callback et verdict.
package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Eizi0/OpenCVEC/internal/canary"
	"github.com/Eizi0/OpenCVEC/internal/checks"
	"github.com/Eizi0/OpenCVEC/internal/netguard"
	"github.com/Eizi0/OpenCVEC/internal/proof"
	"github.com/Eizi0/OpenCVEC/internal/receiver"
	"github.com/Eizi0/OpenCVEC/internal/settings"
)

// Runner exécute les checks en file d'attente avec un nombre borné de workers.
type Runner struct {
	DB     *pgxpool.Pool
	Corr   *receiver.Correlator
	Signer *canary.Signer
	Zone   string
	Log    *slog.Logger
	// HTTPTimeout borne chaque requête vers la cible (10 s par défaut).
	HTTPTimeout time.Duration
	// OnVerdict est appelé après un verdict prouvé, probable ou exposé (notifications).
	OnVerdict func(checkID int64, verdict, summary string)

	queue chan int64
}

// Detail est le contenu JSON de checks.detail.
type Detail struct {
	ResolvedIPs []string          `json:"resolved_ips,omitempty"`
	Canary      string            `json:"canary,omitempty"`
	ExpiresAt   *time.Time        `json:"canary_expires_at,omitempty"`
	WaitSeconds int               `json:"wait_seconds,omitempty"`
	Points      []checks.Point    `json:"points,omitempty"`
	Evidence    map[string]string `json:"evidence,omitempty"`
	Callback    *receiver.Hit     `json:"callback,omitempty"`
	DeltaMS     int64             `json:"delta_ms,omitempty"`
	Error       string            `json:"error,omitempty"`
}

// Start lance les workers et reprend les checks laissés en suspens par un redémarrage.
func (r *Runner) Start(ctx context.Context, workers int) error {
	if r.HTTPTimeout == 0 {
		r.HTTPTimeout = 10 * time.Second
	}
	r.queue = make(chan int64, 1024)
	if _, err := r.DB.Exec(ctx, `UPDATE checks SET status = 'error', verdict = 'error', finished_at = now(),
		summary = 'Interrompu par un redémarrage du serveur.' WHERE status IN ('running', 'waiting')`); err != nil {
		return err
	}
	rows, err := r.DB.Query(ctx, `SELECT id FROM checks WHERE status = 'queued' ORDER BY id`)
	if err != nil {
		return err
	}
	var pending []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			pending = append(pending, id)
		}
	}
	rows.Close()
	for i := 0; i < workers; i++ {
		go r.worker(ctx)
	}
	for _, id := range pending {
		r.queue <- id
	}
	return nil
}

// Enqueue ajoute un check à la file.
func (r *Runner) Enqueue(id int64) {
	select {
	case r.queue <- id:
	default:
		go func() { r.queue <- id }()
	}
}

func (r *Runner) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-r.queue:
			if err := r.run(ctx, id); err != nil {
				r.Log.Error("exécution d'un check", "check", id, "err", err)
				r.finish(context.Background(), id, checks.VerdictError, "Erreur interne : "+err.Error(), Detail{Error: err.Error()}, "error")
			}
		}
	}
}

type job struct {
	id, campaignID, assetID int64
	checker, target         string
	cancelled               bool
	asset                   proof.Asset
}

func (r *Runner) load(ctx context.Context, id int64) (job, error) {
	var j job
	err := r.DB.QueryRow(ctx, `SELECT k.id, k.campaign_id, k.asset_id, k.checker, c.target_url, c.cancelled,
			a.host, a.kind, a.scheme, a.port, a.proof_method
		FROM checks k JOIN campaigns c ON c.id = k.campaign_id JOIN assets a ON a.id = k.asset_id
		WHERE k.id = $1 AND k.status = 'queued'`, id).
		Scan(&j.id, &j.campaignID, &j.assetID, &j.checker, &j.target, &j.cancelled,
			&j.asset.Host, &j.asset.Kind, &j.asset.Scheme, &j.asset.Port, &j.asset.Method)
	j.asset.ID = j.assetID
	return j, err
}

func (r *Runner) setStatus(ctx context.Context, id int64, status string, d Detail, extra string) error {
	b, _ := json.Marshal(d)
	_, err := r.DB.Exec(ctx, `UPDATE checks SET status = $2, detail = $3`+extra+` WHERE id = $1`, id, status, b)
	return err
}

func (r *Runner) finish(ctx context.Context, id int64, verdict, summary string, d Detail, status string) {
	b, _ := json.Marshal(d)
	tag, err := r.DB.Exec(ctx, `UPDATE checks SET status = $2, verdict = $3, summary = $4, detail = $5, finished_at = now()
		WHERE id = $1 AND status NOT IN ('done', 'error', 'cancelled')`, id, status, verdict, summary, b)
	if err != nil {
		r.Log.Error("clôture d'un check", "check", id, "err", err)
		return
	}
	if tag.RowsAffected() == 1 && r.OnVerdict != nil && (verdict == checks.VerdictProved || verdict == checks.VerdictProbable || verdict == checks.VerdictExposed) {
		r.OnVerdict(id, verdict, summary)
	}
}

func (r *Runner) cancelled(ctx context.Context, campaignID int64) bool {
	var c bool
	_ = r.DB.QueryRow(ctx, `SELECT cancelled FROM campaigns WHERE id = $1`, campaignID).Scan(&c)
	return c
}

// Policy construit la politique réseau d'un asset.
func Policy(ctx context.Context, db *pgxpool.Pool, a proof.Asset) (netguard.Policy, error) {
	allow, err := settings.Allowlist(ctx, db)
	if err != nil {
		return netguard.Policy{}, err
	}
	p := netguard.Policy{Allowlist: allow}
	if pr, ok := proof.Prefix(a); ok {
		p.Scope = []netip.Prefix{pr}
	}
	return p, nil
}

func (r *Runner) run(ctx context.Context, id int64) error {
	j, err := r.load(ctx, id)
	if err != nil {
		// Déjà pris en charge ou supprimé : rien à faire.
		return nil
	}
	if j.cancelled {
		r.finish(ctx, id, "", "Campagne annulée avant l'exécution.", Detail{}, "cancelled")
		return nil
	}
	c, ok := checks.Get(j.checker)
	if !ok {
		r.finish(ctx, id, checks.VerdictError, "Checker inconnu : "+j.checker, Detail{}, "error")
		return nil
	}
	st, err := settings.Load(ctx, r.DB)
	if err != nil {
		return err
	}
	pol, err := Policy(ctx, r.DB, j.asset)
	if err != nil {
		return err
	}
	u, err := url.Parse(j.target)
	if err != nil {
		r.finish(ctx, id, checks.VerdictError, "URL cible invalide.", Detail{}, "error")
		return nil
	}
	// Résolution au moment du check : les adresses contactées doivent rester dans le périmètre.
	ips, err := pol.Resolve(ctx, u.Hostname())
	d := Detail{}
	if err != nil {
		d.Error = err.Error()
		r.finish(ctx, id, checks.VerdictError, "Cible hors périmètre ou injoignable : "+err.Error(), d, "error")
		return nil
	}
	for _, ip := range ips {
		d.ResolvedIPs = append(d.ResolvedIPs, ip.String())
	}
	if err := r.setStatus(ctx, id, "running", d, `, started_at = now()`); err != nil {
		return err
	}
	timeout := r.HTTPTimeout
	env := checks.Env{
		Client: pol.Client(timeout),
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return pol.Dial(ctx, network, addr, timeout)
		},
	}
	info := c.Info()
	var fc checks.FileCanary
	if err := r.DB.QueryRow(ctx, `SELECT path, token FROM asset_canaries WHERE asset_id = $1`, j.assetID).Scan(&fc.Path, &fc.Token); err == nil {
		env.File = &fc
	}
	if info.RequiresFileCanary && env.File == nil {
		r.finish(ctx, id, checks.VerdictError, "Ce check exige un canari fichier : générez-le depuis la fiche de l'asset et déposez-le sur la machine.", d, "error")
		return nil
	}

	if info.Mode == checks.ModeFingerprint {
		rctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		out, err := c.Run(rctx, j.target, env)
		cancel()
		if err != nil {
			d.Error = err.Error()
			r.finish(ctx, id, checks.VerdictError, "Échec de la vérification : "+err.Error(), d, "error")
			return nil
		}
		d.Evidence = out.Evidence
		r.finish(ctx, id, out.Verdict, out.Summary, d, "done")
		return nil
	}

	// Mode canari.
	token := r.Signer.New(j.assetID, id)
	exp := time.Now().Add(time.Duration(st.CanaryTTLMinutes) * time.Minute)
	if _, err := r.DB.Exec(ctx, `INSERT INTO canaries (token, check_id, asset_id, expires_at) VALUES ($1, $2, $3, $4)`,
		token, id, j.assetID, exp); err != nil {
		return err
	}
	d.Canary = canary.Host("", token, r.Zone)
	d.ExpiresAt = &exp
	d.WaitSeconds = st.WaitSeconds
	if err := r.setStatus(ctx, id, "running", d, ""); err != nil {
		return err
	}
	hits, unsubscribe := r.Corr.Subscribe(id)
	defer unsubscribe()
	if info.FileCallback && env.File != nil {
		defer r.Corr.ExpectFile(j.assetID, id)()
	}
	env.CanaryHost = func(point string) string { return canary.Host(point, token, r.Zone) }

	// L'heure d'envoi est prise avant la première requête : une cible vulnérable peut résoudre
	// le canari avant même d'avoir répondu.
	sent := time.Now()
	rctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	out, err := c.Run(rctx, j.target, env)
	cancel()
	d.Points = out.Points
	if err != nil {
		d.Error = err.Error()
		r.finish(ctx, id, checks.VerdictError, "Échec de l'envoi : "+err.Error(), d, "error")
		return nil
	}
	// Preuve dans la bande (canari fichier relu) ou verdict direct du plugin : pas d'attente.
	if out.Verdict != "" {
		d.Evidence = out.Evidence
		if _, err := r.DB.Exec(ctx, `UPDATE checks SET sent_at = $2 WHERE id = $1`, id, sent); err != nil {
			return err
		}
		r.finish(ctx, id, out.Verdict, out.Summary, d, "done")
		return nil
	}
	d.Evidence = out.Evidence
	if err := r.setStatus(ctx, id, "waiting", d, ""); err != nil {
		return err
	}
	if _, err := r.DB.Exec(ctx, `UPDATE checks SET sent_at = $2 WHERE id = $1`, id, sent); err != nil {
		return err
	}

	deadline := time.NewTimer(time.Duration(st.WaitSeconds) * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case h := <-hits:
			d.Callback = &h
			d.DeltaMS = h.At.Sub(sent).Milliseconds()
			if d.DeltaMS < 0 {
				d.DeltaMS = 0
			}
			where := ""
			if h.Point == "fichier" {
				where = ", en exfiltrant le contenu du canari fichier " + env.File.Path
			}
			for _, p := range d.Points {
				if p.ID == h.Point {
					where = " via " + p.Location
				}
			}
			summary := fmt.Sprintf("%s : la cible a déclenché le canari (%s %s)%s, %.2f s après le début de l'envoi. %s",
				info.Name, h.Proto, h.QType, where, float64(d.DeltaMS)/1000, out.Summary)
			r.finish(ctx, id, checks.VerdictProved, summary, d, "done")
			return nil
		case <-tick.C:
			if r.cancelled(ctx, j.campaignID) {
				r.finish(ctx, id, "", "Campagne annulée pendant l'attente du callback.", d, "cancelled")
				return nil
			}
		case <-deadline.C:
			r.finish(ctx, id, checks.VerdictInconclusive,
				fmt.Sprintf("Aucun callback reçu en %d s. La cible n'est probablement pas vulnérable, ou ses sorties DNS/HTTP sont filtrées.", st.WaitSeconds), d, "done")
			return nil
		}
	}
}
