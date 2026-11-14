package plugin

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Eizi0/OpenCVEC/internal/checks"
	"github.com/Eizi0/OpenCVEC/internal/netguard"
)

func loopbackEnv() checks.Env {
	pol := netguard.Policy{Allowlist: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	return checks.Env{
		Client:     pol.Client(3 * time.Second),
		Dial:       func(ctx context.Context, n, a string) (net.Conn, error) { return pol.Dial(ctx, n, a, 3*time.Second) },
		CanaryHost: func(p string) string { return p + ".abcdefghijklmnopqrst.c.test" },
	}
}

func TestOfficialPluginsAreValid(t *testing.T) {
	files, _ := filepath.Glob("../../plugins/*.yaml")
	if len(files) < 3 {
		t.Fatalf("plugins officiels introuvables : %v", files)
	}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		if _, err := Parse(b); err != nil {
			t.Errorf("%s : %v", f, err)
		}
	}
}

const base = `
id: test-plugin
name: TestChecker
version: 1.0.0
cves: [CVE-2099-0001]
description: d
sent: s
remediation: [r]
`

func TestValidationRejectsOutOfScopeAndUnsafe(t *testing.T) {
	cases := map[string]string{
		"URL absolue":           "mode: canary\nproofs: {callback: true}\nsteps:\n  - id: a\n    http: {path: 'http://evil.example/{{canary.dns.p1}}'}\n",
		"chemin protocole-rel.": "mode: canary\nproofs: {callback: true}\nsteps:\n  - id: a\n    http: {path: '//evil.example/{{canary.dns.p1}}'}\n",
		"en-tête Host":          "mode: canary\nproofs: {callback: true}\nsteps:\n  - id: a\n    http: {path: '/x', headers: {Host: evil.example, X: '{{canary.dns.p1}}'}}\n",
		"variable inconnue":     "mode: canary\nproofs: {callback: true}\nsteps:\n  - id: a\n    http: {path: '/x?{{env.SECRET}}{{canary.dns.p1}}'}\n",
		"canari sans usage":     "mode: canary\nproofs: {callback: true}\nsteps:\n  - id: a\n    http: {path: '/x'}\n",
		"empreinte avec canari": "mode: fingerprint\nsteps:\n  - id: a\n    http: {path: '/{{canary.dns.p1}}'}\nmatchers:\n  - {step: a, status: [200], verdict: exposed}\n",
		"champ inconnu":         "mode: canary\nproofs: {callback: true}\ncommand: 'rm -rf /'\nsteps:\n  - id: a\n    http: {path: '/{{canary.dns.p1}}'}\n",
		"injection CRLF":        "mode: canary\nproofs: {callback: true}\nsteps:\n  - id: a\n    http: {path: '/x', headers: {X: \"a\\r\\nHost: evil\"}, body: '{{canary.dns.p1}}'}\n",
		"fichier non utilisé":   "mode: canary\nproofs: {file_in_response: true}\nsteps:\n  - id: a\n    http: {path: '/x'}\n",
	}
	for name, body := range cases {
		if _, err := Parse([]byte(base + body)); err == nil {
			t.Errorf("%s : plugin accepté à tort", name)
		}
	}
	ok := base + "mode: canary\nproofs: {callback: true}\nsteps:\n  - id: a\n    http: {path: '/x?q={{canary.dns.p1}}'}\n"
	if _, err := Parse([]byte(ok)); err != nil {
		t.Fatalf("plugin valide refusé : %v", err)
	}
}

func TestFileCanaryReadInResponse(t *testing.T) {
	const token = "zzyyxxwwvvuuttssrrqq"
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.RawPath+r.URL.Path)
		// Cible vulnérable simulée : la traversée par /cgi-bin/ renvoie le fichier demandé.
		if strings.HasPrefix(r.URL.EscapedPath(), "/cgi-bin/.%2e/") && strings.HasSuffix(r.URL.Path, "/opt/opencvec/canary.txt") {
			io.WriteString(w, "OPENCVEC-CANARY "+strings.ToUpper(token)+"\n")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	b, _ := os.ReadFile("../../plugins/apache-path-traversal-cve-2021-41773.yaml")
	p, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	c := &Checker{P: p, Publisher: "test", Signed: true}
	env := loopbackEnv()
	if _, err := c.Run(context.Background(), srv.URL+"/", env); err == nil {
		t.Fatal("sans canari fichier, le check doit échouer")
	}
	env.File = &checks.FileCanary{Path: "/opt/opencvec/canary.txt", Token: token}
	out, err := c.Run(context.Background(), srv.URL+"/", env)
	if err != nil || out.Verdict != checks.VerdictProved {
		t.Fatalf("verdict %q, err %v, chemins %v", out.Verdict, err, paths)
	}
	for _, v := range out.Evidence {
		if strings.Contains(strings.ToLower(v), token) {
			t.Fatal("le contenu de la réponse ne doit pas être conservé")
		}
	}
	// Patché : le fichier n'est pas renvoyé.
	safe := httptest.NewServer(http.NotFoundHandler())
	defer safe.Close()
	out, err = c.Run(context.Background(), safe.URL+"/", env)
	if err != nil || out.Verdict != checks.VerdictInconclusive {
		t.Fatalf("cible corrigée : %q %v", out.Verdict, err)
	}
}

func fakeSSH(t *testing.T, banner string) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			io.WriteString(c, banner+"\r\n")
			c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func TestRegreSSHionBanner(t *testing.T) {
	b, _ := os.ReadFile("../../plugins/regresshion-cve-2024-6387.yaml")
	p, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	c := &Checker{P: p, Publisher: "test", Signed: true}
	cases := map[string]string{
		"SSH-2.0-OpenSSH_9.6p1":                   checks.VerdictProbable,
		"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1": checks.VerdictProbable,
		"SSH-2.0-OpenSSH_9.8p1":                   checks.VerdictPatched,
		"SSH-2.0-OpenSSH_8.4p1 Debian-5":          checks.VerdictPatched,
		"SSH-2.0-OpenSSH_4.3p2":                   checks.VerdictProbable,
		"SSH-2.0-dropbear_2022.83":                checks.VerdictInconclusive,
	}
	for banner, want := range cases {
		addr := fakeSSH(t, banner)
		_, port, _ := net.SplitHostPort(addr)
		// Le port de la bannière vient de l'URL cible quand default_port est surchargé par l'asset.
		p.DefaultPort = 0
		out, err := c.Run(context.Background(), "http://127.0.0.1:"+port+"/", loopbackEnv())
		if err != nil || out.Verdict != want {
			t.Errorf("%s : verdict %q (attendu %q) err %v — %s", banner, out.Verdict, want, err, out.Summary)
		}
		if want == checks.VerdictProbable && !strings.Contains(out.Summary, banner) {
			t.Errorf("le message doit citer la bannière : %s", out.Summary)
		}
	}
}

func TestTCPStepIsConfined(t *testing.T) {
	b, _ := os.ReadFile("../../plugins/regresshion-cve-2024-6387.yaml")
	p, _ := Parse(b)
	c := &Checker{P: p}
	env := loopbackEnv()
	pol := netguard.Policy{} // boucle locale non autorisée
	env.Dial = func(ctx context.Context, n, a string) (net.Conn, error) { return pol.Dial(ctx, n, a, time.Second) }
	addr := fakeSSH(t, "SSH-2.0-OpenSSH_9.6p1")
	_, port, _ := net.SplitHostPort(addr)
	p.DefaultPort = 0
	if _, err := c.Run(context.Background(), "http://127.0.0.1:"+port+"/", env); err == nil || !strings.Contains(err.Error(), "périmètre") {
		t.Fatalf("connexion hors périmètre non bloquée : %v", err)
	}
}

func TestCallbackPluginWaits(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("spring.cloud.function.routing-expression")
	}))
	defer srv.Close()
	b, _ := os.ReadFile("../../plugins/spring-cloud-function-cve-2022-22963.yaml")
	p, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	out, err := (&Checker{P: p}).Run(context.Background(), srv.URL+"/", loopbackEnv())
	if err != nil || out.Verdict != "" {
		t.Fatalf("un plugin à callback doit laisser le runner attendre : %q %v", out.Verdict, err)
	}
	if got != `T(java.net.InetAddress).getByName("p1.abcdefghijklmnopqrst.c.test")` {
		t.Fatalf("en-tête reçu : %q", got)
	}
}

func TestSignature(t *testing.T) {
	pubT, keyT, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := ParsePublicKey(pubT)
	key, _ := ParsePrivateKey(keyT)
	data := []byte(base + "mode: canary\n")
	sig := Sign(key, data)
	trusted := []Publisher{{Name: "Officiel", Key: pub}}
	if p, err := Verify(data, sig, trusted); err != nil || p.Name != "Officiel" {
		t.Fatalf("signature valide refusée : %v", err)
	}
	if _, err := Verify(append(data, '#'), sig, trusted); err == nil {
		t.Fatal("fichier modifié accepté")
	}
	if _, err := Verify(data, "", trusted); err != ErrUnsigned {
		t.Fatal("absence de signature non signalée")
	}
	otherPub, _, _ := GenerateKey()
	op, _ := ParsePublicKey(otherPub)
	if _, err := Verify(data, sig, []Publisher{{Name: "Autre", Key: op}}); err == nil {
		t.Fatal("signature d'un éditeur non approuvé acceptée")
	}
}

func TestRanges(t *testing.T) {
	r, _ := parseRange(">=8.5.1, <9.8.1")
	for v, want := range map[string]bool{"8.5.1": true, "9.7.1": true, "9.8.1": false, "8.4.1": false, "9.6": true} {
		pv, _ := parseVersion(v)
		if r.contains(pv) != want {
			t.Errorf("%s : %v", v, !want)
		}
	}
}
