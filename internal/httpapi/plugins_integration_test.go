package httpapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/miekg/dns"

	"github.com/Eizi0/OpenCVEC/internal/plugin"
	officialplugins "github.com/Eizi0/OpenCVEC/plugins"
)

// publisher crée une clé d'éditeur de test et l'approuve via l'API.
func (e *env) publisher(admin *client) func(data []byte) string {
	pubT, keyT, err := plugin.GenerateKey()
	if err != nil {
		e.t.Fatal(err)
	}
	admin.json("POST", "/api/publishers", map[string]any{"name": "Éditeur de test", "public_key": pubT}, nil, 201)
	key, _ := plugin.ParsePrivateKey(keyT)
	return func(data []byte) string { return plugin.Sign(key, data) }
}

func TestPluginTrustAndFileCanaryInBand(t *testing.T) {
	e := newEnv(t)
	admin := e.login("admin@test")
	analyst := e.login("analyste@test")
	data, _ := os.ReadFile("../../plugins/apache-path-traversal-cve-2021-41773.yaml")

	// Non signé : refusé.
	if st, body := admin.do("POST", "/api/plugins", map[string]any{"content": string(data)}); st != 400 || !strings.Contains(body, "non signé") {
		t.Fatalf("plugin non signé accepté : %d %s", st, body)
	}
	// Signé par un éditeur non approuvé : refusé.
	_, otherKey, _ := plugin.GenerateKey()
	ok, _ := plugin.ParsePrivateKey(otherKey)
	if st, _ := admin.do("POST", "/api/plugins", map[string]any{"content": string(data), "signature": plugin.Sign(ok, data)}); st != 400 {
		t.Fatalf("éditeur non approuvé accepté : %d", st)
	}
	sign := e.publisher(admin)
	// Signature valide mais contenu modifié : refusé.
	if st, _ := admin.do("POST", "/api/plugins", map[string]any{"content": string(data) + "\n# ajout", "signature": sign(data)}); st != 400 {
		t.Fatalf("plugin modifié après signature accepté : %d", st)
	}
	// Analyste : pas le droit d'installer.
	if st, _ := analyst.do("POST", "/api/plugins", map[string]any{"content": string(data), "signature": sign(data)}); st != 403 {
		t.Fatalf("installation par un analyste : %d", st)
	}
	var pv pluginPreview
	admin.json("POST", "/api/plugins/preview", map[string]any{"content": string(data), "signature": sign(data)}, &pv, 200)
	if !pv.Signed || pv.Publisher != "Éditeur de test" || !pv.RequiresFileCanary || len(pv.Steps) != 2 {
		t.Fatalf("aperçu : %+v", pv)
	}
	admin.json("POST", "/api/plugins", map[string]any{"content": string(data), "signature": sign(data)}, nil, 201)

	// Cible simulée vulnérable à la traversée : renvoie le fichier demandé s'il s'agit du canari.
	var token string
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.EscapedPath(), "/icons/.%2e/") && strings.HasSuffix(r.URL.Path, "/opt/opencvec/canary.txt") && token != "" {
			io.WriteString(w, token+"\n")
			return
		}
		http.NotFound(w, r)
	}))
	defer vuln.Close()
	assetID := e.ownedLoopbackAsset(admin)

	// Sans canari fichier : erreur explicite.
	var c1 struct{ ID int64 }
	analyst.json("POST", "/api/campaigns", map[string]any{"asset_id": assetID, "target_url": vuln.URL + "/", "checkers": []string{"apache-traversal-41773"}}, &c1, 201)
	if camp := analyst.waitCampaign(c1.ID); camp.Checks[0].Verdict != "error" || !strings.Contains(camp.Checks[0].Summary, "canari fichier") {
		t.Fatalf("sans canari fichier : %+v", camp.Checks[0])
	}
	var fc fileCanary
	analyst.json("POST", "/api/assets/"+itoa(assetID)+"/canary", map[string]any{"path": "/opt/opencvec/canary.txt"}, &fc, 200)
	if !strings.Contains(fc.Linux, fc.Token) {
		t.Fatalf("instructions de dépôt : %+v", fc)
	}
	if st, _ := analyst.do("POST", "/api/assets/"+itoa(assetID)+"/canary", map[string]any{"path": "/tmp/x; rm -rf /"}); st != 400 {
		t.Fatal("chemin de canari dangereux accepté")
	}
	token = fc.Token // le canari est « déposé » sur la cible
	var c2 struct{ ID int64 }
	analyst.json("POST", "/api/campaigns", map[string]any{"asset_id": assetID, "target_url": vuln.URL + "/", "checkers": []string{"apache-traversal-41773"}}, &c2, 201)
	camp := analyst.waitCampaign(c2.ID)
	if camp.Checks[0].Verdict != "proved" || !strings.Contains(camp.Checks[0].Summary, "relu") {
		t.Fatalf("canari fichier relu : %+v", camp.Checks[0])
	}
	if strings.Contains(string(camp.Checks[0].Detail), token) {
		t.Fatal("le contenu de la réponse (jeton) ne doit pas être stocké dans le détail du check")
	}

	// Désactivation : le checker disparaît du catalogue et ne peut plus être lancé.
	admin.json("PUT", "/api/plugins/apache-traversal-41773", map[string]any{"enabled": false}, nil, 200)
	if st, _ := analyst.do("POST", "/api/campaigns", map[string]any{"asset_id": assetID, "target_url": vuln.URL + "/", "checkers": []string{"apache-traversal-41773"}}); st != 400 {
		t.Fatalf("plugin désactivé encore utilisable : %d", st)
	}
	// Retrait de l'éditeur : le plugin réactivé ne se charge plus.
	admin.json("PUT", "/api/plugins/apache-traversal-41773", map[string]any{"enabled": true}, nil, 200)
	var pubs []struct {
		ID      int64
		Builtin bool
	}
	admin.json("GET", "/api/publishers", nil, &pubs, 200)
	for _, p := range pubs {
		if !p.Builtin {
			admin.json("DELETE", "/api/publishers/"+itoa(p.ID), nil, nil, 200)
		}
	}
	if st, _ := analyst.do("POST", "/api/campaigns", map[string]any{"asset_id": assetID, "target_url": vuln.URL + "/", "checkers": []string{"apache-traversal-41773"}}); st != 400 {
		t.Fatalf("plugin d'un éditeur retiré encore utilisable : %d", st)
	}
}

const exfilPlugin = `id: test-exfil
name: ExfilChecker
version: 1.0.0
cves: [CVE-2099-0002]
description: Test d'exfiltration du canari fichier par DNS.
sent: une requête GET
remediation: [corriger]
mode: canary
steps:
  - id: rce
    http:
      path: "/run?cmd=cat%20{{canary.file.path}}"
proofs:
  file_callback: true
`

func TestFileCanaryExfiltrationAndHoneytoken(t *testing.T) {
	e := newEnv(t)
	admin := e.login("admin@test")
	sign := e.publisher(admin)
	admin.json("POST", "/api/plugins", map[string]any{"content": exfilPlugin, "signature": sign([]byte(exfilPlugin))}, nil, 201)
	assetID := e.ownedLoopbackAsset(admin)
	var fc fileCanary
	admin.json("POST", "/api/assets/"+itoa(assetID)+"/canary", map[string]any{"path": "/srv/canary.txt"}, &fc, 200)

	exfil := func() {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(fc.Token+"."+zone), dns.TypeA)
		_, _ = dns.Exchange(m, e.dnsSrv)
	}
	// Cible simulée exécutant la commande : elle lit le canari et l'exfiltre par DNS.
	rce := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cmd") == "cat /srv/canary.txt" {
			exfil()
		}
	}))
	defer rce.Close()
	var c struct{ ID int64 }
	admin.json("POST", "/api/campaigns", map[string]any{"asset_id": assetID, "target_url": rce.URL + "/", "checkers": []string{"test-exfil"}}, &c, 201)
	camp := admin.waitCampaign(c.ID)
	if camp.Checks[0].Verdict != "proved" || !strings.Contains(camp.Checks[0].Summary, "exfiltrant") {
		t.Fatalf("exfiltration du canari fichier : %+v", camp.Checks[0])
	}

	// Hors check : le même jeton déclenche une alerte de compromission, une seule pour des
	// requêtes répétées (A, AAAA, nouvelles tentatives).
	exfil()
	exfil()
	exfil()
	var alerts []Callback
	for i := 0; i < 50 && len(alerts) == 0; i++ {
		admin.json("GET", "/api/callbacks?status=alerts", nil, &alerts, 200)
	}
	if len(alerts) != 1 || alerts[0].AssetHost != "127.0.0.1" {
		t.Fatalf("alerte de jeton piège attendue : %+v", alerts)
	}
	var n int
	_ = e.db.QueryRow(context.Background(), `SELECT count(*) FROM callbacks WHERE status = 'honeytoken'`).Scan(&n)
	if n != 1 {
		t.Fatalf("%d alertes enregistrées", n)
	}
}

func TestUnsignedPluginInDevMode(t *testing.T) {
	e := newEnv(t)
	admin := e.login("admin@test")
	admin.json("PUT", "/api/settings", map[string]any{"canary_ttl_minutes": 15, "wait_seconds": 60, "checks_per_asset_day": 10, "checks_per_user_hour": 60, "allow_unsigned_plugins": true}, nil, 200)
	admin.json("POST", "/api/plugins", map[string]any{"content": exfilPlugin}, nil, 201)
	var list []pluginRow
	admin.json("GET", "/api/plugins", nil, &list, 200)
	var unsigned *pluginRow
	for i := range list {
		if list[i].ID == "test-exfil" {
			unsigned = &list[i]
		}
	}
	if unsigned == nil || unsigned.Signed || len(list) != 11 {
		t.Fatalf("10 plugins officiels + 1 non signé attendus : %+v", list)
	}
	var n int
	_ = e.db.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action = 'Mode développeur' OR detail LIKE '%NON SIGNÉ%'`).Scan(&n)
	if n != 2 {
		t.Fatalf("mode développeur et installation non signée doivent être journalisés (%d)", n)
	}
	// Retour en mode normal : le plugin non signé n'est plus chargé.
	admin.json("PUT", "/api/settings", map[string]any{"canary_ttl_minutes": 15, "wait_seconds": 60, "checks_per_asset_day": 10, "checks_per_user_hour": 60, "allow_unsigned_plugins": false}, nil, 200)
	var cat []struct{ ID string }
	admin.json("GET", "/api/checkers", nil, &cat, 200)
	for _, c := range cat {
		if c.ID == "test-exfil" {
			t.Fatal("plugin non signé encore chargé hors mode développeur")
		}
	}
}

func TestOfficialPreinstall(t *testing.T) {
	e := newEnv(t) // newEnv préinstalle déjà les plugins officiels
	ctx := context.Background()
	admin := e.login("admin@test")
	store := &plugin.Store{DB: e.db, Log: nil, Official: plugin.OfficialPublicKey}

	var list []pluginRow
	admin.json("GET", "/api/plugins", nil, &list, 200)
	if len(list) != 10 {
		t.Fatalf("10 plugins officiels préinstallés attendus, %d", len(list))
	}
	for _, p := range list {
		if !p.Signed || p.Publisher != plugin.OfficialName || !strings.HasPrefix(p.Source, "préinstallé") {
			t.Fatalf("plugin préinstallé incorrect : %+v", p)
		}
	}
	// Idempotent : rien à refaire au redémarrage.
	if done, err := store.Preinstall(ctx, officialplugins.FS); err != nil || len(done) != 0 {
		t.Fatalf("seconde préinstallation : %v %v", done, err)
	}
	// Une désinstallation volontaire est respectée au redémarrage.
	admin.json("DELETE", "/api/plugins/fortibleed", nil, nil, 200)
	if done, _ := store.Preinstall(ctx, officialplugins.FS); len(done) != 0 {
		t.Fatalf("plugin désinstallé réinstallé : %v", done)
	}
	// Une version plus ancienne en base est mise à jour.
	if _, err := e.db.Exec(ctx, `UPDATE plugins SET version = '1.0.0' WHERE id = 'log4shell'`); err != nil {
		t.Fatal(err)
	}
	if done, _ := store.Preinstall(ctx, officialplugins.FS); len(done) != 1 || !strings.HasPrefix(done[0], "log4shell ") {
		t.Fatalf("mise à jour attendue : %v", done)
	}
	// Un binaire dont un plugin officiel a été altéré est refusé.
	altered := fstest.MapFS{}
	data, _ := officialplugins.FS.ReadFile("log4shell.yaml")
	sig, _ := officialplugins.FS.ReadFile("log4shell.yaml.sig")
	altered["log4shell.yaml"] = &fstest.MapFile{Data: append(data, []byte("\n# altéré")...)}
	altered["log4shell.yaml.sig"] = &fstest.MapFile{Data: sig}
	if _, err := store.Preinstall(ctx, altered); err == nil {
		t.Fatal("plugin officiel altéré accepté")
	}
}
