package plugin

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Eizi0/OpenCVEC/internal/checks"
)

// Checker adapte un plugin à l'interface checks.Checker.
type Checker struct {
	P         *Plugin
	Publisher string
	Signed    bool
}

// Info renvoie la fiche du catalogue.
func (c *Checker) Info() checks.Info {
	p := c.P
	mode := checks.ModeFingerprint
	if p.Mode == "canary" {
		mode = checks.ModeCanary
	}
	note := p.LabNote
	if note == "" {
		note = "Pas de validation en labo documentée."
	}
	return checks.Info{
		ID: p.ID, Name: p.Name, CVEs: p.CVEs, Product: p.Product, Mode: mode, Description: p.Description,
		Proof: p.Proof, Sent: p.Sent, Remediation: p.Remediation, References: p.References, Tags: p.Tags,
		LabValidated: p.LabValidated, LabNote: note, Source: "plugin", Version: p.Version, Publisher: c.Publisher, Signed: c.Signed,
		RequiresFileCanary: p.RequiresFileCanary(),
		FileCallback:       p.Proofs != nil && p.Proofs.FileCallback,
	}
}

// response est la réponse d'une étape, gardée en mémoire le temps du check seulement.
type response struct {
	status  int
	headers http.Header
	body    []byte
}

func (r response) part(p string) string {
	switch {
	case p == "" || p == "body":
		return string(r.body)
	case p == "status":
		return strconv.Itoa(r.status)
	case strings.HasPrefix(p, "header:"):
		return strings.Join(r.headers.Values(p[7:]), "\n")
	}
	var sb strings.Builder
	keys := make([]string, 0, len(r.headers))
	for k := range r.headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&sb, "%s: %s\n", k, strings.Join(r.headers[k], ", "))
	}
	sb.WriteString("\n")
	sb.Write(r.body)
	return sb.String()
}

func randomHex() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// render remplace les variables d'un gabarit.
func render(s string, vars map[string]string, env checks.Env) string {
	return varRe.ReplaceAllStringFunc(s, func(m string) string {
		v := strings.TrimSpace(m[2 : len(m)-2])
		switch {
		case strings.HasPrefix(v, "canary.dns."):
			if env.CanaryHost != nil {
				return env.CanaryHost(v[len("canary.dns."):])
			}
		case strings.HasPrefix(v, "canary.url."):
			if env.CanaryHost != nil {
				return "http://" + env.CanaryHost(v[len("canary.url."):]) + "/"
			}
		case v == "canary.file.path":
			if env.File != nil {
				return env.File.Path
			}
		default:
			if x, ok := vars[v]; ok {
				return x
			}
		}
		return ""
	})
}

// Run exécute les étapes et rend un verdict (empreinte, ou canari fichier relu) ou laisse le
// runner attendre un callback.
func (c *Checker) Run(ctx context.Context, target string, env checks.Env) (checks.Outcome, error) {
	p := c.P
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return checks.Outcome{}, fmt.Errorf("URL cible invalide")
	}
	if p.RequiresFileCanary() && env.File == nil {
		return checks.Outcome{}, fmt.Errorf("aucun canari fichier n'est déposé sur cet asset")
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"https": "443", "http": "80"}[u.Scheme]
	}
	vars := map[string]string{
		"target.host": u.Hostname(), "target.port": port, "target.base": u.Scheme + "://" + u.Host,
		"target.path": u.EscapedPath(), "target.dir": strings.TrimRight(u.EscapedPath(), "/"),
		"target.url": target, "random": randomHex(),
	}
	if vars["target.path"] == "" {
		vars["target.path"] = "/"
	}

	resps := map[string]response{}
	var points []checks.Point
	sentAny := false
	ev := map[string]string{}
	extracted := map[string]string{}
	for _, st := range p.Steps {
		if !st.When.holds(extracted) {
			continue
		}
		pt := checks.Point{ID: st.ID}
		var r response
		var err error
		if st.HTTP != nil {
			pt.Location = st.HTTP.Method + " " + render(st.HTTP.Path, vars, env)
			if st.HTTP.Path == "" {
				pt.Location = st.HTTP.Method + " " + u.RequestURI()
			}
			r, err = c.doHTTP(ctx, u, st.HTTP, vars, env)
		} else {
			tp := st.TCP.Port
			if tp == 0 {
				tp = p.DefaultPort
			}
			if tp == 0 {
				tp, _ = strconv.Atoi(port)
			}
			pt.Location = fmt.Sprintf("TCP %d%s", tp, map[bool]string{true: " (TLS)", false: ""}[st.TCP.TLS])
			r, err = c.doTCP(ctx, u.Hostname(), tp, st.TCP, vars, env)
		}
		if err != nil {
			pt.Error = errText(err)
		} else {
			sentAny = true
			pt.Status = r.status
			resps[st.ID] = r
			extractFrom(p, st.ID, r, extracted, ev)
			// Preuve dans la bande : le contenu du canari fichier apparaît dans la réponse.
			if p.Proofs != nil && p.Proofs.FileInResponse && env.File != nil &&
				strings.Contains(strings.ToLower(r.part("all")), strings.ToLower(env.File.Token)) {
				points = append(points, pt)
				return checks.Outcome{
					Verdict: checks.VerdictProved, Points: points,
					Summary: fmt.Sprintf("%s : le contenu du canari fichier (%s) a été relu dans la réponse de l'étape « %s ». La faille permet de lire un fichier arbitraire de l'asset.", p.Name, env.File.Path, st.ID),
					Evidence: map[string]string{"Étape": st.ID, "Requête": pt.Location, "Statut": strconv.Itoa(r.status), "Canari fichier": env.File.Path,
						"Contenu de la réponse": "non conservé (seule la présence du jeton est enregistrée)"},
				}, nil
			}
		}
		points = append(points, pt)
		// Libellés des points de canari de l'étape : le runner s'en sert pour nommer le point déclenché.
		for _, id := range sortedKeys(st.Points) {
			points = append(points, checks.Point{ID: id, Location: st.Points[id], Status: pt.Status, Error: pt.Error})
		}
	}
	if !sentAny {
		return checks.Outcome{Points: points}, fmt.Errorf("aucune étape n'a pu être exécutée : %s", points[0].Error)
	}

	if p.Mode == "canary" {
		if p.Proofs.Callback || p.Proofs.FileCallback {
			ids := make([]string, 0, len(points))
			for _, pt := range points {
				ids = append(ids, pt.ID)
			}
			return checks.Outcome{Summary: fmt.Sprintf("Étapes envoyées : %s.", strings.Join(ids, ", ")), Points: points, Evidence: ev}, nil
		}
		return checks.Outcome{Verdict: checks.VerdictInconclusive, Points: points, Evidence: ev,
			Summary: fmt.Sprintf("%s : le contenu du canari fichier n'a été relu dans aucune réponse. L'asset n'est probablement pas vulnérable (ou le canari n'est pas déposé à %s).", p.Name, env.File.Path)}, nil
	}

	// Empreinte : matchers puis règle de version.
	for _, m := range p.Matchers {
		if !m.When.holds(extracted) || !condHolds(m.Cond, resps) {
			continue
		}
		all := true
		for _, c := range m.Also {
			all = all && condHolds(c, resps)
		}
		if !all {
			continue
		}
		return checks.Outcome{Verdict: m.Verdict, Summary: render(m.Message, extracted, env), Points: points, Evidence: ev}, nil
	}
	if rule := p.Rule; rule != nil {
		raw, ok := extracted[rule.Var]
		if !ok {
			msg := rule.Missing
			if msg == "" {
				msg = "Version non trouvée : l'empreinte n'est pas exposée."
			}
			return checks.Outcome{Verdict: checks.VerdictInconclusive, Summary: msg, Points: points, Evidence: ev}, nil
		}
		v, ok := parseVersion(raw)
		if !ok {
			return checks.Outcome{Verdict: checks.VerdictInconclusive, Summary: "Version illisible : " + raw, Points: points, Evidence: ev}, nil
		}
		for _, rr := range rule.Vulnerable {
			rg, _ := parseRange(rr.Range)
			if rg.contains(v) {
				verdict := rr.Verdict
				if verdict == "" {
					verdict = checks.VerdictProbable
				}
				msg := rr.Message
				if msg == "" {
					msg = fmt.Sprintf("Version %s dans la plage %s.", raw, rr.Range)
				}
				return checks.Outcome{Verdict: verdict, Summary: render(msg, extracted, env), Points: points, Evidence: ev}, nil
			}
		}
		msg := rule.Patched
		if msg == "" {
			msg = "Version " + raw + " hors des plages vulnérables."
		}
		return checks.Outcome{Verdict: checks.VerdictPatched, Summary: render(msg, extracted, env), Points: points, Evidence: ev}, nil
	}
	msg := p.Fallback
	if msg == "" {
		msg = "Aucune condition du plugin n'est remplie."
	}
	return checks.Outcome{Verdict: checks.VerdictInconclusive, Summary: render(msg, extracted, env), Points: points, Evidence: ev}, nil
}

// extractFrom applique les extractions d'une étape (la première valeur trouvée est gardée).
func extractFrom(p *Plugin, step string, r response, extracted, ev map[string]string) {
	for _, e := range p.Extract {
		if e.Step != step || extracted[e.Name] != "" {
			continue
		}
		m := regexp.MustCompile(e.Regex).FindStringSubmatch(r.part(e.Part))
		if m == nil {
			continue
		}
		val := ""
		switch {
		case e.Format != "":
			val = e.Format
			for i := len(m) - 1; i >= 0; i-- {
				val = strings.ReplaceAll(val, "{"+strconv.Itoa(i)+"}", m[i])
			}
		case len(m) > 1:
			val = m[1]
		default:
			val = m[0]
		}
		if len(val) > 200 {
			val = val[:200]
		}
		extracted[e.Name] = val
		ev[e.Name] = val
	}
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := strconv.Atoi(out[i][1:])
		b, _ := strconv.Atoi(out[j][1:])
		return a < b
	})
	return out
}

func condHolds(c Cond, resps map[string]response) bool {
	r, ok := resps[c.Step]
	return ok && matches(c, r)
}

func matches(m Cond, r response) bool {
	if len(m.Status) > 0 {
		ok := false
		for _, s := range m.Status {
			ok = ok || s == r.status
		}
		if !ok {
			return false
		}
	}
	txt := r.part(m.Part)
	if len(m.Contains) > 0 {
		low := strings.ToLower(txt)
		ok := false
		for _, c := range m.Contains {
			ok = ok || strings.Contains(low, strings.ToLower(c))
		}
		if !ok {
			return false
		}
	}
	if m.Regex != "" && !regexp.MustCompile(m.Regex).MatchString(txt) {
		return false
	}
	return true
}

func (c *Checker) doHTTP(ctx context.Context, base *url.URL, h *HTTPStep, vars map[string]string, env checks.Env) (response, error) {
	if env.Client == nil {
		return response{}, fmt.Errorf("client HTTP indisponible")
	}
	target := base.String()
	if h.Path != "" {
		// Seul le chemin vient du plugin : schéma, hôte et port sont ceux de l'asset.
		target = base.Scheme + "://" + base.Host + render(h.Path, vars, env)
	}
	var body io.Reader
	if h.Body != "" {
		body = strings.NewReader(render(h.Body, vars, env))
	}
	req, err := http.NewRequestWithContext(ctx, h.Method, target, body)
	if err != nil {
		return response{}, err
	}
	if req.URL.Host != base.Host {
		return response{}, fmt.Errorf("le chemin rendu sort de l'asset")
	}
	req.Header.Set("User-Agent", "OpenCVEC/0.2 (+verification de vulnerabilite autorisee)")
	// La casse des en-têtes est conservée telle que l'auteur l'a écrite : certaines applications
	// (Spring, par exemple) les lisent en respectant la casse, contrairement à la norme HTTP.
	for k, v := range h.Headers {
		req.Header.Del(k)
		req.Header[k] = []string{render(v, vars, env)}
	}
	resp, err := env.Client.Do(req)
	if err != nil {
		return response{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return response{status: resp.StatusCode, headers: resp.Header, body: b}, nil
}

func (c *Checker) doTCP(ctx context.Context, host string, port int, t *TCPStep, vars map[string]string, env checks.Env) (response, error) {
	if env.Dial == nil {
		return response{}, fmt.Errorf("connexion TCP indisponible")
	}
	timeout := 5 * time.Second
	if t.Timeout != "" {
		timeout, _ = time.ParseDuration(t.Timeout)
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := env.Dial(cctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return response{}, err
	}
	defer conn.Close()
	if t.TLS {
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: host}) //nolint:gosec // assets internes
		if err := tc.HandshakeContext(cctx); err != nil {
			return response{}, err
		}
		conn = tc
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	var payload []byte
	if t.SendHex != "" {
		payload, _ = hex.DecodeString(strings.ReplaceAll(t.SendHex, " ", ""))
	} else {
		payload = []byte(render(t.Send, vars, env))
	}
	if len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			return response{}, err
		}
	}
	n := t.ReadBytes
	if n == 0 {
		n = 4096
	}
	var buf bytes.Buffer
	_, err = io.CopyN(&buf, conn, int64(n))
	if buf.Len() == 0 && err != nil {
		return response{}, fmt.Errorf("aucune donnée reçue : %w", err)
	}
	return response{body: buf.Bytes()}, nil
}

func errText(err error) string {
	if ue, ok := err.(*url.Error); ok {
		err = ue.Err
	}
	s := err.Error()
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
