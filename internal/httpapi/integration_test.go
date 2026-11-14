package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/miekg/dns"

	"github.com/Eizi0/OpenCVEC/internal/audit"
	"github.com/Eizi0/OpenCVEC/internal/auth"
	"github.com/Eizi0/OpenCVEC/internal/canary"
	"github.com/Eizi0/OpenCVEC/internal/config"
	"github.com/Eizi0/OpenCVEC/internal/notify"
	"github.com/Eizi0/OpenCVEC/internal/plugin"
	"github.com/Eizi0/OpenCVEC/internal/proof"
	"github.com/Eizi0/OpenCVEC/internal/receiver"
	"github.com/Eizi0/OpenCVEC/internal/runner"
	"github.com/Eizi0/OpenCVEC/internal/secrets"
	"github.com/Eizi0/OpenCVEC/internal/testdb"
	officialplugins "github.com/Eizi0/OpenCVEC/plugins"
)

const zone = "c.opencvec.test"

type env struct {
	t      *testing.T
	srv    *Server
	db     *pgxpool.Pool
	api    *httptest.Server
	dnsSrv string
	corr   *receiver.Correlator
	signer *canary.Signer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db := testdb.New(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	signer, _ := canary.NewSigner(bytes.Repeat([]byte{9}, 32))
	corr := &receiver.Correlator{DB: db, Signer: signer, Zone: zone, Log: log}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ds := &dns.Server{PacketConn: pc, Handler: &receiver.DNSHandler{C: corr, Zone: zone, NSName: "ns1." + zone, IP: net.ParseIP("127.0.0.1")}}
	go func() { _ = ds.ActivateAndServe() }()
	t.Cleanup(func() { _ = ds.Shutdown() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	box0, _ := secrets.New("")
	notifier := &notify.Notifier{DB: db, Box: box0, PublicURL: "https://opencvec.test", Log: log}
	corr.OnHoneytoken = func(assetID int64, ev receiver.Event) { notifier.Honeytoken(ev.Source, "test") }
	run := &runner.Runner{DB: db, Corr: corr, Signer: signer, Zone: zone, Log: log, HTTPTimeout: 3 * time.Second, OnVerdict: notifier.Verdict}
	if err := run.Start(ctx, 2); err != nil {
		t.Fatal(err)
	}
	box, _ := secrets.New("")
	srv := &Server{
		Cfg: config.Config{CanaryZone: zone, NSName: "ns1." + zone, CanaryIP: "127.0.0.1"}, DB: db, Log: log, Secrets: box,
		Audit: &audit.Log{DB: db}, Runner: run, Corr: corr, Verifier: proof.Verifier{},
		Plugins: &plugin.Store{DB: db, Log: log, Official: plugin.OfficialPublicKey}, Notifier: notifier,
	}
	if err := srv.Plugins.EnsureOfficial(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Plugins.Preinstall(ctx, officialplugins.FS); err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(srv.Handler())
	t.Cleanup(api.Close)
	for _, u := range []struct{ email, role string }{{"admin@test", "admin"}, {"analyste@test", "analyst"}, {"lecteur@test", "viewer"}} {
		h, _ := auth.HashPassword("motdepasse-solide")
		if _, err := db.Exec(ctx, `INSERT INTO users (email, role, password_hash) VALUES ($1, $2, $3)`, u.email, u.role, h); err != nil {
			t.Fatal(err)
		}
	}
	return &env{t: t, srv: srv, db: db, api: api, dnsSrv: pc.LocalAddr().String(), corr: corr, signer: signer}
}

type client struct {
	e  *env
	hc *http.Client
}

func (e *env) login(email string) *client {
	jar, _ := cookiejar.New(nil)
	c := &client{e: e, hc: &http.Client{Jar: jar}}
	st, body := c.do("POST", "/api/login", map[string]string{"email": email, "password": "motdepasse-solide"})
	if st != 200 {
		e.t.Fatalf("connexion %s : %d %s", email, st, body)
	}
	return c
}

func (c *client) do(method, path string, in any) (int, string) {
	c.e.t.Helper()
	var r io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.e.api.URL+path, r)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(csrfHeader, "1")
	resp, err := c.hc.Do(req)
	if err != nil {
		c.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (c *client) json(method, path string, in, out any, want int) {
	c.e.t.Helper()
	st, body := c.do(method, path, in)
	if st != want {
		c.e.t.Fatalf("%s %s : statut %d (attendu %d) : %s", method, path, st, want, body)
	}
	if out != nil {
		if err := json.Unmarshal([]byte(body), out); err != nil {
			c.e.t.Fatalf("%s %s : %v", method, path, err)
		}
	}
}

// vulnerable simule une application Log4j vulnérable : elle résout, via le DNS du récepteur,
// tout nom placé dans un lookup JNDI.
func (e *env) vulnerable() *httptest.Server {
	re := regexp.MustCompile(`\$\{jndi:ldap://([^/}]+)/a\}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m := re.FindStringSubmatch(r.Header.Get("X-Api-Version")); m != nil {
			msg := new(dns.Msg)
			msg.SetQuestion(dns.Fqdn(m[1]), dns.TypeA)
			_, _ = dns.Exchange(msg, e.dnsSrv)
		}
		io.WriteString(w, "ok")
	}))
	e.t.Cleanup(srv.Close)
	return srv
}

func (e *env) ownedLoopbackAsset(admin *client) int64 {
	admin.json("POST", "/api/allowlist", map[string]any{"cidr": "127.0.0.0/8", "reason": "labo de test"}, nil, 201)
	var a Asset
	admin.json("POST", "/api/assets", map[string]any{"host": "127.0.0.1", "proof_method": "allowlist", "scheme": "http"}, &a, 201)
	if a.Owned {
		e.t.Fatal("un asset neuf ne doit pas être prouvé")
	}
	admin.json("POST", "/api/assets/"+itoa(a.ID)+"/verify", nil, &a, 200)
	if !a.Owned {
		e.t.Fatalf("preuve par liste blanche refusée : %s", a.ProofDetail)
	}
	return a.ID
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func (c *client) waitCampaign(id int64) Campaign {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var camp Campaign
		c.json("GET", "/api/campaigns/"+itoa(id), nil, &camp, 200)
		if camp.Pending == 0 {
			return camp
		}
		time.Sleep(200 * time.Millisecond)
	}
	c.e.t.Fatal("campagne non terminée en 30 s")
	return Campaign{}
}

func TestEndToEndCanaryProof(t *testing.T) {
	e := newEnv(t)
	admin := e.login("admin@test")
	assetID := e.ownedLoopbackAsset(admin)
	vuln := e.vulnerable()

	var created struct{ ID int64 }
	admin.json("POST", "/api/campaigns", map[string]any{"asset_id": assetID, "target_url": vuln.URL + "/app", "checkers": []string{"log4shell", "php2shell"}}, &created, 201)
	camp := admin.waitCampaign(created.ID)
	verdicts := map[string]string{}
	for _, k := range camp.Checks {
		verdicts[k.Checker] = k.Verdict
	}
	if verdicts["log4shell"] != "proved" {
		t.Fatalf("Log4Shell : verdict %q, attendu proved (%+v)", verdicts["log4shell"], camp.Checks)
	}
	if verdicts["php2shell"] != "inconclusive" {
		t.Fatalf("PHP2Shell sans en-tête : verdict %q", verdicts["php2shell"])
	}

	var proved Check
	for _, k := range camp.Checks {
		if k.Checker == "log4shell" {
			proved = k
		}
	}
	var det CheckDetail
	admin.json("GET", "/api/checks/"+itoa(proved.ID), nil, &det, 200)
	if len(det.Callbacks) == 0 || det.Callbacks[0].Status != "correlated" || det.Callbacks[0].Point != "p2" {
		t.Fatalf("callback corrélé attendu sur p2 (X-Api-Version) : %+v", det.Callbacks)
	}
	if !strings.Contains(det.Summary, "X-Api-Version") {
		t.Fatalf("le résumé doit nommer le point d'injection : %s", det.Summary)
	}

	// Un callback reçu après le verdict est un rejeu.
	var d struct{ Canary string }
	_ = json.Unmarshal(det.Detail, &d)
	st, err := e.corr.Record(context.Background(), receiver.Event{Proto: "dns", QType: "A", QName: "p2." + d.Canary, Source: "127.0.0.1"})
	if err != nil || st != receiver.StatusReplay {
		t.Fatalf("rejeu : statut %q, err %v", st, err)
	}

	// Rapport et intégrité de l'audit.
	var rep struct {
		ID     int64
		SHA256 string
	}
	admin.json("POST", "/api/reports", map[string]any{"campaign_id": created.ID, "format": "html", "include_raw": true, "include_inconclusive": true}, &rep, 201)
	_, html := admin.do("GET", "/api/reports/"+itoa(rep.ID)+"/download", nil)
	if !strings.Contains(html, "Prouvé vulnérable") || !strings.Contains(html, d.Canary) {
		t.Fatal("le rapport doit contenir le verdict et le canari")
	}
	var v audit.VerifyResult
	admin.json("GET", "/api/audit/verify", nil, &v, 200)
	if !v.OK || v.Count < 5 {
		t.Fatalf("chaîne d'audit : %+v", v)
	}
	if _, err := e.db.Exec(context.Background(), `UPDATE audit_log SET detail = 'falsifié'`); err == nil {
		t.Fatal("le journal d'audit doit refuser les modifications")
	}
}

func TestNotVulnerableIsInconclusive(t *testing.T) {
	e := newEnv(t)
	admin := e.login("admin@test")
	if _, err := e.db.Exec(context.Background(), `INSERT INTO settings (key, value) VALUES ('general', '{"canary_ttl_minutes":5,"wait_seconds":15,"checks_per_asset_day":10,"checks_per_user_hour":60}')`); err != nil {
		t.Fatal(err)
	}
	assetID := e.ownedLoopbackAsset(admin)
	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer safe.Close()
	var created struct{ ID int64 }
	admin.json("POST", "/api/campaigns", map[string]any{"asset_id": assetID, "target_url": safe.URL, "checkers": []string{"text4shell"}}, &created, 201)
	time.Sleep(14 * time.Second)
	camp := admin.waitCampaign(created.ID)
	if camp.Checks[0].Verdict != "inconclusive" {
		t.Fatalf("verdict %q, attendu inconclusive", camp.Checks[0].Verdict)
	}
}

func TestAntiAbuseRefusals(t *testing.T) {
	e := newEnv(t)
	admin := e.login("admin@test")
	analyst := e.login("analyste@test")
	viewer := e.login("lecteur@test")

	// Asset non prouvé : refus.
	var a Asset
	analyst.json("POST", "/api/assets", map[string]any{"host": "shop.exemple.fr", "proof_method": "dns_txt"}, &a, 201)
	if a.TXTName != "_opencvec.shop.exemple.fr" || !strings.HasPrefix(a.TXTValue, "opencvec-verif=") {
		t.Fatalf("instructions de preuve : %+v", a)
	}
	st, body := analyst.do("POST", "/api/campaigns", map[string]any{"asset_id": a.ID, "checkers": []string{"log4shell"}})
	if st != http.StatusForbidden || !strings.Contains(body, "non prouvée") {
		t.Fatalf("check sur asset non prouvé : %d %s", st, body)
	}

	ownedID := e.ownedLoopbackAsset(admin)
	// Payload ou URL de callback personnalisés : champ inconnu refusé.
	st, _ = analyst.do("POST", "/api/campaigns", map[string]any{"asset_id": ownedID, "checkers": []string{"log4shell"}, "callback_url": "http://evil.example/x"})
	if st != http.StatusBadRequest {
		t.Fatalf("champ callback_url accepté : %d", st)
	}
	st, _ = analyst.do("POST", "/api/campaigns", map[string]any{"asset_id": ownedID, "checkers": []string{"log4shell"}, "payload": "${jndi:ldap://evil/a}"})
	if st != http.StatusBadRequest {
		t.Fatalf("champ payload accepté : %d", st)
	}
	// Cible hors de l'asset.
	st, body = analyst.do("POST", "/api/campaigns", map[string]any{"asset_id": ownedID, "target_url": "http://10.0.0.5/", "checkers": []string{"log4shell"}})
	if st != http.StatusBadRequest || !strings.Contains(body, "127.0.0.1") {
		t.Fatalf("cible hors périmètre : %d %s", st, body)
	}
	// Checker inconnu.
	if st, _ = analyst.do("POST", "/api/campaigns", map[string]any{"asset_id": ownedID, "checkers": []string{"rce-generique"}}); st != http.StatusBadRequest {
		t.Fatalf("checker inconnu accepté : %d", st)
	}
	// Rôle lecteur.
	if st, _ = viewer.do("POST", "/api/campaigns", map[string]any{"asset_id": ownedID, "checkers": []string{"log4shell"}}); st != http.StatusForbidden {
		t.Fatalf("lecteur autorisé à lancer un check : %d", st)
	}
	// Analyste sans droits d'administration.
	if st, _ = analyst.do("POST", "/api/allowlist", map[string]any{"cidr": "10.0.0.0/8", "reason": "x"}); st != http.StatusForbidden {
		t.Fatalf("analyste autorisé à modifier la liste blanche : %d", st)
	}
	// CSRF : en-tête manquant.
	req, _ := http.NewRequest("POST", e.api.URL+"/api/campaigns", strings.NewReader(`{}`))
	resp, _ := analyst.hc.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("requête sans en-tête CSRF acceptée : %d", resp.StatusCode)
	}
	// Limite de débit par asset.
	admin.json("PUT", "/api/settings", map[string]any{"canary_ttl_minutes": 15, "wait_seconds": 60, "checks_per_asset_day": 1, "checks_per_user_hour": 60}, nil, 200)
	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("X-Powered-By", "PHP/8.4.30") }))
	defer safe.Close()
	analyst.json("POST", "/api/campaigns", map[string]any{"asset_id": ownedID, "target_url": safe.URL, "checkers": []string{"php2shell"}}, nil, 201)
	if st, _ = analyst.do("POST", "/api/campaigns", map[string]any{"asset_id": ownedID, "target_url": safe.URL, "checkers": []string{"php2shell"}}); st != http.StatusTooManyRequests {
		t.Fatalf("limite par asset non appliquée : %d", st)
	}
	// Retrait de la liste blanche : l'asset perd sa preuve.
	var allow []allowRow
	admin.json("GET", "/api/allowlist", nil, &allow, 200)
	admin.json("DELETE", "/api/allowlist/"+itoa(allow[0].ID), nil, nil, 200)
	var after Asset
	admin.json("GET", "/api/assets/"+itoa(ownedID), nil, &after, 200)
	if after.Owned {
		t.Fatal("l'asset doit perdre sa preuve quand sa plage quitte la liste blanche")
	}

	// Chaque refus est journalisé.
	var n int
	_ = e.db.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action = 'Refus'`).Scan(&n)
	if n < 3 {
		t.Fatalf("refus non journalisés (%d)", n)
	}
}

func TestCorrelatorRejectsForgedAndExpired(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.login("admin@test")
	assetID := e.ownedLoopbackAsset(admin)
	var cid, kid int64
	_ = e.db.QueryRow(ctx, `INSERT INTO campaigns (asset_id, target_url) VALUES ($1, 'http://127.0.0.1/') RETURNING id`, assetID).Scan(&cid)
	_ = e.db.QueryRow(ctx, `INSERT INTO checks (campaign_id, asset_id, checker, status) VALUES ($1, $2, 'log4shell', 'waiting') RETURNING id`, cid, assetID).Scan(&kid)

	// Jeton bien formé mais non signé pour ce check.
	forged := e.signer.New(assetID, kid+1)
	_, _ = e.db.Exec(ctx, `INSERT INTO canaries (token, check_id, asset_id, expires_at) VALUES ($1, $2, $3, now() + interval '10 minutes')`, forged, kid, assetID)
	if st, _ := e.corr.Record(ctx, receiver.Event{Proto: "dns", QName: forged + "." + zone, Source: "1.2.3.4"}); st != receiver.StatusUnknown {
		t.Fatalf("jeton forgé : %q", st)
	}
	_, _ = e.db.Exec(ctx, `DELETE FROM canaries`)

	tok := e.signer.New(assetID, kid)
	_, _ = e.db.Exec(ctx, `INSERT INTO canaries (token, check_id, asset_id, expires_at) VALUES ($1, $2, $3, now() - interval '1 minute')`, tok, kid, assetID)
	if st, _ := e.corr.Record(ctx, receiver.Event{Proto: "dns", QName: "p1." + tok + "." + zone, Source: "1.2.3.4"}); st != receiver.StatusExpired {
		t.Fatalf("canari expiré : %q", st)
	}
	_, _ = e.db.Exec(ctx, `UPDATE canaries SET expires_at = now() + interval '10 minutes'`)
	if st, _ := e.corr.Record(ctx, receiver.Event{Proto: "dns", QName: "p1." + tok + "." + zone, Source: "1.2.3.4"}); st != receiver.StatusCorrelated {
		t.Fatalf("premier callback valide : %q", st)
	}
	if st, _ := e.corr.Record(ctx, receiver.Event{Proto: "dns", QName: "p1." + tok + "." + zone, Source: "1.2.3.4"}); st != receiver.StatusDuplicate {
		t.Fatalf("second callback : %q", st)
	}
	if st, _ := e.corr.Record(ctx, receiver.Event{Proto: "dns", QName: "aaaaaaaaaaaaaaaaaaaa." + zone, Source: "1.2.3.4"}); st != receiver.StatusUnknown {
		t.Fatalf("jeton inconnu : %q", st)
	}
	if st, _ := e.corr.Record(ctx, receiver.Event{Proto: "dns", QName: "www.exemple.fr", Source: "1.2.3.4"}); st != "" {
		t.Fatalf("nom hors zone enregistré : %q", st)
	}
}
