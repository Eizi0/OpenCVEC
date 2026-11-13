package checks

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

func init() {
	register(php2shell{})
	register(wp2shell{})
	register(fortiExposure{})
}

func get(ctx context.Context, env Env, u string) (*http.Response, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	return send(ctx, env.Client, req)
}

// ---------------------------------------------------------------------------------------------
// PHP2Shell : CVE-2026-109618 et CVE-2026-109619 (corruption mémoire dans le moteur PHP).
// Aucune preuve active sans exploit de corruption mémoire : on se limite à la version exposée.

type php2shell struct{}

// Dernière version vulnérable de chaque branche corrigée : le correctif est la version suivante.
var php2shellFixed = map[[2]int]version{
	{8, 2}: {8, 2, 35},
	{8, 3}: {8, 3, 36},
	{8, 4}: {8, 4, 27},
	{8, 5}: {8, 5, 12},
}

func (php2shell) Info() Info {
	return Info{
		ID: "php2shell", Name: "PHP2ShellChecker", CVEs: []string{"CVE-2026-109618", "CVE-2026-109619"},
		Product: "PHP 5.4 à 8.5 (corrigé en 8.2.35, 8.3.36, 8.4.27, 8.5.12)", Mode: ModeFingerprint, Tags: []string{"php"},
		Description: "Lit la version de PHP annoncée par le serveur (en-tête X-Powered-By) et la compare aux versions corrigées. Les deux CVE sont des corruptions mémoire exploitées activement : aucune charge n'est envoyée.",
		Proof:       "Empreinte de version (verdict « probable » au mieux)",
		Sent:        "Une requête GET ordinaire sur l'URL cible.",
		Remediation: []string{"Mettre PHP à jour : 8.2.35, 8.3.36, 8.4.27 ou 8.5.12 au minimum.", "Les branches 8.1 et antérieures ne reçoivent pas de correctif : migrer.", "Une distribution peut avoir rétroporté le correctif sans changer le numéro : vérifier le paquet installé.", "Désactiver expose_php pour ne plus annoncer la version."},
		References:  []string{"https://blog.qualys.com/vulnerabilities-threat-research/2026/10/20/php-announces-critical-security-release-for-two-vulnerabilities", "https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/"},
		LabNote:     "Comparaison de versions couverte par les tests ; à revalider en labo avec une image php vulnérable.",
	}
}

var phpPowered = regexp.MustCompile(`(?i)PHP/(\d+\.\d+(?:\.\d+)?)`)

// php2shellVerdict décide à partir d'une version de PHP.
func php2shellVerdict(raw string) (string, string) {
	v, ok := parseVersion(raw)
	if !ok {
		return VerdictInconclusive, "Version de PHP illisible : " + raw
	}
	if v.less(version{5, 4, 0}) {
		return VerdictInconclusive, fmt.Sprintf("PHP %s : antérieur à la plage décrite par l'avis (5.4+), obsolète de toute façon.", v)
	}
	if fixed, ok := php2shellFixed[v.branch()]; ok {
		if v.less(fixed) {
			return VerdictProbable, fmt.Sprintf("PHP %s annoncé : vulnérable d'après sa version (corrigé en %s).", v, fixed)
		}
		return VerdictPatched, fmt.Sprintf("PHP %s annoncé : version corrigée.", v)
	}
	if v.less(version{8, 2, 0}) {
		return VerdictProbable, fmt.Sprintf("PHP %s annoncé : branche sans correctif publié, vulnérable sauf rétroportage.", v)
	}
	return VerdictInconclusive, fmt.Sprintf("PHP %s : branche non couverte par l'avis.", v)
}

func (php2shell) Run(ctx context.Context, target string, env Env) (Outcome, error) {
	resp, _, err := get(ctx, env, target)
	if err != nil {
		return Outcome{}, err
	}
	ev := map[string]string{"HTTP": fmt.Sprint(resp.StatusCode)}
	for _, h := range []string{"X-Powered-By", "Server"} {
		if v := resp.Header.Get(h); v != "" {
			ev[h] = v
		}
	}
	m := phpPowered.FindStringSubmatch(resp.Header.Get("X-Powered-By") + " " + resp.Header.Get("Server"))
	if m == nil {
		return Outcome{Verdict: VerdictInconclusive, Summary: "Le serveur n'annonce pas sa version de PHP (expose_php désactivé ou PHP absent).", Evidence: ev}, nil
	}
	verdict, summary := php2shellVerdict(m[1])
	return Outcome{Verdict: verdict, Summary: summary, Evidence: ev}, nil
}

// ---------------------------------------------------------------------------------------------
// WP2Shell : CVE-2026-63030 (confusion de routes REST batch) + CVE-2026-60137 (injection SQL).

type wp2shell struct{}

func (wp2shell) Info() Info {
	return Info{
		ID: "wp2shell", Name: "WP2ShellChecker", CVEs: []string{"CVE-2026-63030", "CVE-2026-60137"},
		Product: "WordPress 6.8.0 à 6.8.5, 6.9.0 à 6.9.4, 7.0.0 à 7.0.1", Mode: ModeFingerprint, Tags: []string{"wordpress", "php"},
		Description: "Détermine la version de WordPress (balise generator de la page d'accueil, puis flux RSS) et la compare aux versions corrigées. La chaîne mène à une exécution de code sans authentification ; elle n'est jamais déclenchée.",
		Proof:       "Empreinte de version (verdict « probable » au mieux)",
		Sent:        "Deux requêtes GET ordinaires : la page d'accueil et /feed/.",
		Remediation: []string{"Mettre WordPress à jour : 6.8.6, 6.9.5 ou 7.0.2 au minimum.", "Vérifier que la mise à jour automatique forcée a bien été appliquée.", "Rechercher des comptes administrateurs ou extensions inconnus créés depuis juillet 2026."},
		References:  []string{"https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core/", "https://www.vulncheck.com/blog/wp2shell"},
		LabNote:     "Comparaison de versions couverte par les tests ; à revalider en labo avec une image wordpress vulnérable.",
	}
}

var (
	wpGenerator = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s+(\d+\.\d+(?:\.\d+)?)`)
	wpFeedGen   = regexp.MustCompile(`(?i)<generator>https?://wordpress\.org/\?v=(\d+\.\d+(?:\.\d+)?)</generator>`)
)

func wp2shellVerdict(raw string) (string, string) {
	v, ok := parseVersion(raw)
	if !ok {
		return VerdictInconclusive, "Version de WordPress illisible : " + raw
	}
	switch v.branch() {
	case [2]int{6, 8}:
		if v.less(version{6, 8, 6}) {
			return VerdictProbable, fmt.Sprintf("WordPress %s : exposé à l'injection SQL CVE-2026-60137 (pas à la chaîne complète). Corrigé en 6.8.6.", v)
		}
		return VerdictPatched, fmt.Sprintf("WordPress %s : version corrigée.", v)
	case [2]int{6, 9}:
		if v.less(version{6, 9, 5}) {
			return VerdictProbable, fmt.Sprintf("WordPress %s : chaîne wp2shell complète (exécution de code sans authentification). Corrigé en 6.9.5.", v)
		}
		return VerdictPatched, fmt.Sprintf("WordPress %s : version corrigée.", v)
	case [2]int{7, 0}:
		if v.less(version{7, 0, 2}) {
			return VerdictProbable, fmt.Sprintf("WordPress %s : chaîne wp2shell complète (exécution de code sans authentification). Corrigé en 7.0.2.", v)
		}
		return VerdictPatched, fmt.Sprintf("WordPress %s : version corrigée.", v)
	}
	if v.less(version{6, 8, 0}) {
		return VerdictInconclusive, fmt.Sprintf("WordPress %s : branche antérieure non décrite par l'avis, et obsolète : mettre à jour.", v)
	}
	return VerdictPatched, fmt.Sprintf("WordPress %s : postérieur aux versions corrigées.", v)
}

func (wp2shell) Run(ctx context.Context, target string, env Env) (Outcome, error) {
	ev := map[string]string{}
	resp, body, err := get(ctx, env, target)
	if err != nil {
		return Outcome{}, err
	}
	ev["HTTP accueil"] = fmt.Sprint(resp.StatusCode)
	if m := wpGenerator.FindSubmatch(body); m != nil {
		ev["Source"] = "balise meta generator"
		ev["Version"] = string(m[1])
		v, s := wp2shellVerdict(string(m[1]))
		return Outcome{Verdict: v, Summary: s, Evidence: ev}, nil
	}
	if resp, body, err := get(ctx, env, joinURL(target, "feed/")); err == nil {
		ev["HTTP /feed/"] = fmt.Sprint(resp.StatusCode)
		if m := wpFeedGen.FindSubmatch(body); m != nil {
			ev["Source"] = "flux RSS"
			ev["Version"] = string(m[1])
			v, s := wp2shellVerdict(string(m[1]))
			return Outcome{Verdict: v, Summary: s, Evidence: ev}, nil
		}
	}
	if strings.Contains(string(body), "/wp-content/") || strings.Contains(string(body), "/wp-includes/") {
		return Outcome{Verdict: VerdictInconclusive, Summary: "WordPress détecté, mais sa version est masquée : vérifier depuis l'administration.", Evidence: ev}, nil
	}
	return Outcome{Verdict: VerdictInconclusive, Summary: "WordPress non détecté sur cette URL.", Evidence: ev}, nil
}

// ---------------------------------------------------------------------------------------------
// FortiBleed : campagne de vol d'identifiants (juin 2026), pas une CVE. Le risque mesurable de
// l'extérieur est l'exposition des interfaces d'administration et du portail SSL-VPN.

type fortiExposure struct{}

func (fortiExposure) Info() Info {
	return Info{
		ID: "fortibleed", Name: "FortiBleedChecker", CVEs: []string{"CVE-2026-24858", "CVE-2025-59718", "CVE-2024-55591"},
		Product: "FortiGate / FortiOS (interfaces d'administration et SSL-VPN)", Mode: ModeFingerprint, Tags: []string{"fortinet", "périmètre"},
		Description: "« FortiBleed » désigne une campagne de vol d'identifiants, pas une faille unique. Le check repère depuis l'extérieur ce qui l'a rendue possible : une interface d'administration FortiGate ou un portail SSL-VPN joignable. Les CVE listées sont celles que les avis associent à la campagne ; leurs versions ne sont pas visibles de l'extérieur.",
		Proof:       "Exposition constatée (verdict « exposé »)",
		Sent:        "Deux requêtes GET ordinaires : /login et /remote/login.",
		Remediation: []string{"Restreindre l'administration aux hôtes de confiance (trusted hosts, local-in policy).", "Faire tourner les mots de passe des comptes administrateurs et VPN, imposer la double authentification.", "Vérifier l'absence de comptes inconnus (show system admin) et appliquer les avis FG-IR-26-060, FG-IR-25-647, FG-IR-24-535.", "Désactiver FortiCloud SSO s'il n'est pas utilisé."},
		References:  []string{"https://www.cyber.gc.ca/en/alerts-advisories/al26-014-fortibleed-leak-thousands-compromised-credentials-impacting-fortinet-devices", "https://kudelskisecurity.com/research/fortinet-fortibleed-global-compromise-active-exploitation-of-fortinet-vulnerabilities"},
		LabNote:     "Détection couverte par les tests ; pas d'image FortiGate libre pour le labo.",
	}
}

var fortiMarkers = []string{"fgt_lang", "ftnt-fortinet-grid", "/remote/fgt_lang", "fortinet", "fortigate", "sslvpn_login", "fortitoken"}

func looksForti(resp *http.Response, body []byte) bool {
	s := strings.ToLower(string(body))
	for _, m := range fortiMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	for _, c := range resp.Cookies() {
		n := strings.ToUpper(c.Name)
		if strings.HasPrefix(n, "APSCOOKIE") || n == "SVPNCOOKIE" || n == "SVPNTMPCOOKIE" || n == "CCSRFTOKEN" {
			return true
		}
	}
	return strings.Contains(strings.ToLower(resp.Header.Get("Server")), "xxxxxxxx-xxxxx")
}

func (fortiExposure) Run(ctx context.Context, target string, env Env) (Outcome, error) {
	base := origin(target)
	ev := map[string]string{}
	var exposed []string
	var errs int
	for _, p := range []struct{ path, label string }{{"login", "interface d'administration"}, {"remote/login", "portail SSL-VPN"}} {
		resp, body, err := get(ctx, env, joinURL(base, p.path))
		if err != nil {
			ev["/"+p.path] = errText(err)
			errs++
			continue
		}
		ev["/"+p.path] = fmt.Sprintf("HTTP %d", resp.StatusCode)
		if resp.StatusCode < 500 && looksForti(resp, body) {
			exposed = append(exposed, p.label)
		}
	}
	if errs == 2 {
		return Outcome{}, fmt.Errorf("cible injoignable : %s", ev["/login"])
	}
	if len(exposed) == 0 {
		return Outcome{Verdict: VerdictInconclusive, Summary: "Aucune interface FortiGate reconnue sur cette URL.", Evidence: ev}, nil
	}
	return Outcome{Verdict: VerdictExposed, Summary: "FortiGate exposé sur Internet : " + strings.Join(exposed, " et ") + ". Vérifier identifiants, double authentification et correctifs.", Evidence: ev}, nil
}
