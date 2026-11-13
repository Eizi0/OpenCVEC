package checks

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Eizi0/OpenCVEC/internal/netguard"
)

func env(t *testing.T) Env {
	t.Helper()
	p := netguard.Policy{Allowlist: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	return Env{
		Client:     p.Client(3 * time.Second),
		CanaryHost: func(pt string) string { return pt + ".abcdefghijklmnopqrst.c.test" },
	}
}

// recorder simule une cible vulnérable : elle « résout » tout nom qu'elle évaluerait.
type recorder struct {
	mu    sync.Mutex
	hosts []string
}

func (r *recorder) add(h string) { r.mu.Lock(); r.hosts = append(r.hosts, h); r.mu.Unlock() }
func (r *recorder) has(sub string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, h := range r.hosts {
		if strings.Contains(h, sub) {
			return true
		}
	}
	return false
}

func allInputs(r *http.Request) []string {
	_ = r.ParseForm()
	var vals []string
	for _, vs := range r.Header {
		vals = append(vals, vs...)
	}
	for _, vs := range r.Form {
		vals = append(vals, vs...)
	}
	return vals
}

func TestLog4ShellInjectsEveryPoint(t *testing.T) {
	rec := &recorder{}
	re := regexp.MustCompile(`\$\{jndi:ldap://([^/}]+)/a\}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, v := range allInputs(r) {
			if m := re.FindStringSubmatch(v); m != nil {
				rec.add(m[1])
			}
		}
	}))
	defer srv.Close()
	c, _ := Get("log4shell")
	out, err := c.Run(context.Background(), srv.URL+"/solr/admin/cores", env(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Points) != 12 {
		t.Fatalf("12 points d'injection attendus, %d", len(out.Points))
	}
	for _, p := range out.Points {
		if p.Error != "" || p.Status != 200 {
			t.Fatalf("point %s en échec : %+v", p.ID, p)
		}
		if !rec.has(p.ID + ".abcdefghijklmnopqrst.c.test") {
			t.Errorf("point %s (%s) non reçu par la cible", p.ID, p.Location)
		}
	}
}

func TestText4ShellPayload(t *testing.T) {
	rec := &recorder{}
	re := regexp.MustCompile(`\$\{dns:address\|([^}]+)\}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, v := range allInputs(r) {
			if m := re.FindStringSubmatch(v); m != nil {
				rec.add(m[1])
			}
		}
	}))
	defer srv.Close()
	c, _ := Get("text4shell")
	out, err := c.Run(context.Background(), srv.URL+"/text4shell/attack", env(t))
	if err != nil {
		t.Fatal(err)
	}
	if !rec.has("p2.abcdefghijklmnopqrst") || !rec.has("p7.abcdefghijklmnopqrst") || len(out.Points) != 8 {
		t.Fatalf("payload Text4Shell incomplet : %v", rec.hosts)
	}
}

func TestConfluenceOGNLPath(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.URL.Path }))
	defer srv.Close()
	c, _ := Get("confluence-ognl")
	if _, err := c.Run(context.Background(), srv.URL, env(t)); err != nil {
		t.Fatal(err)
	}
	want := `/${(#a=@java.net.InetAddress@getByName("p1.abcdefghijklmnopqrst.c.test"))}/`
	if got != want {
		t.Fatalf("chemin reçu %q, attendu %q", got, want)
	}
}

func TestPHPCGIPayloadIsDNSOnly(t *testing.T) {
	var queries, bodies []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		queries = append(queries, r.URL.Path+"?"+r.URL.RawQuery)
		bodies = append(bodies, string(b))
		mu.Unlock()
	}))
	defer srv.Close()
	c, _ := Get("php-cgi-4577")
	if _, err := c.Run(context.Background(), srv.URL+"/app/", env(t)); err != nil {
		t.Fatal(err)
	}
	if len(queries) != 2 || !strings.HasPrefix(queries[0], "/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1") || !strings.HasPrefix(queries[1], "/index.php?%ADd") {
		t.Fatalf("requêtes inattendues : %v", queries)
	}
	for i, b := range bodies {
		want := "<?php gethostbyname('p" + string(rune('1'+i)) + ".abcdefghijklmnopqrst.c.test'); ?>"
		if b != want {
			t.Fatalf("corps %d = %q, attendu %q", i, b, want)
		}
	}
}

func TestCanaryCheckerUnreachableIsError(t *testing.T) {
	c, _ := Get("log4shell")
	_, err := c.Run(context.Background(), "http://127.0.0.1:1/", env(t))
	if err == nil {
		t.Fatal("une cible injoignable doit donner une erreur, pas un « non concluant »")
	}
}

func TestOutOfScopeTargetIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("la requête n'aurait pas dû partir")
	}))
	defer srv.Close()
	e := env(t)
	e.Client = netguard.Policy{}.Client(time.Second) // boucle locale non autorisée
	c, _ := Get("log4shell")
	if _, err := c.Run(context.Background(), srv.URL, e); err == nil || !strings.Contains(err.Error(), "périmètre") {
		t.Fatalf("erreur de périmètre attendue, reçu %v", err)
	}
}

func TestPHP2ShellVersions(t *testing.T) {
	cases := map[string]string{
		"8.3.35": VerdictProbable, "8.3.36": VerdictPatched, "8.3.40": VerdictPatched,
		"8.2.34": VerdictProbable, "8.4.27": VerdictPatched, "8.5.11": VerdictProbable,
		"8.1.31": VerdictProbable, "7.4.33": VerdictProbable, "5.3.29": VerdictInconclusive,
		"8.6.0": VerdictInconclusive,
	}
	for v, want := range cases {
		if got, _ := php2shellVerdict(v); got != want {
			t.Errorf("PHP %s : %s, attendu %s", v, got, want)
		}
	}
}

func TestPHP2ShellReadsHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.3.30")
	}))
	defer srv.Close()
	c, _ := Get("php2shell")
	out, err := c.Run(context.Background(), srv.URL, env(t))
	if err != nil || out.Verdict != VerdictProbable {
		t.Fatalf("verdict %q, err %v", out.Verdict, err)
	}
}

func TestWP2ShellVersions(t *testing.T) {
	cases := map[string]string{
		"6.9.4": VerdictProbable, "6.9.5": VerdictPatched, "7.0.1": VerdictProbable, "7.0.2": VerdictPatched,
		"6.8.5": VerdictProbable, "6.8.6": VerdictPatched, "6.7.2": VerdictInconclusive, "7.1": VerdictPatched,
	}
	for v, want := range cases {
		if got, _ := wp2shellVerdict(v); got != want {
			t.Errorf("WordPress %s : %s, attendu %s", v, got, want)
		}
	}
}

func TestWP2ShellFeedFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/feed/" {
			io.WriteString(w, "<rss><channel><generator>https://wordpress.org/?v=7.0.1</generator></channel></rss>")
			return
		}
		io.WriteString(w, `<html><link rel="stylesheet" href="/wp-content/themes/x/style.css"></html>`)
	}))
	defer srv.Close()
	c, _ := Get("wp2shell")
	out, err := c.Run(context.Background(), srv.URL+"/", env(t))
	if err != nil || out.Verdict != VerdictProbable || out.Evidence["Source"] != "flux RSS" {
		t.Fatalf("%+v %v", out, err)
	}
}

func TestFortiExposure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/remote/login" {
			http.SetCookie(w, &http.Cookie{Name: "SVPNTMPCOOKIE", Value: "x"})
			io.WriteString(w, `<script src="/remote/fgt_lang?lang=en"></script>`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c, _ := Get("fortibleed")
	out, err := c.Run(context.Background(), srv.URL+"/whatever", env(t))
	if err != nil || out.Verdict != VerdictExposed || !strings.Contains(out.Summary, "SSL-VPN") {
		t.Fatalf("%+v %v", out, err)
	}
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello") }))
	defer plain.Close()
	out, err = c.Run(context.Background(), plain.URL, env(t))
	if err != nil || out.Verdict != VerdictInconclusive {
		t.Fatalf("%+v %v", out, err)
	}
}

func TestCatalog(t *testing.T) {
	all := All()
	if len(all) != 7 {
		t.Fatalf("7 checkers attendus, %d", len(all))
	}
	for _, i := range all {
		if i.ID == "" || len(i.CVEs) == 0 || i.Sent == "" || len(i.Remediation) == 0 {
			t.Errorf("fiche incomplète : %+v", i)
		}
	}
	_ = url.Values{}
}
