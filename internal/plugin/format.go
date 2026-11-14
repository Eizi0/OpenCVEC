// Package plugin charge, vérifie et exécute les plugins de check au format YAML.
//
// Un plugin décrit des étapes (requêtes HTTP ou échanges TCP/TLS) que le moteur d'OpenCVEC
// exécute lui-même : les requêtes ne peuvent viser que l'asset du check (un chemin ou un port,
// jamais une URL ou un hôte), à travers la garde réseau. La preuve repose uniquement sur les
// canaris : callback DNS/HTTP, contenu du canari fichier relu dans une réponse ou exfiltré par
// DNS. Le moteur ne conserve jamais le corps des réponses, seulement les valeurs extraites.
package plugin

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Limites du format.
const (
	MaxSize      = 256 << 10
	maxSteps     = 20
	maxBody      = 64 << 10
	maxRead      = 64 << 10
	maxStepDelay = 30 * time.Second
)

// Plugin est le contenu d'un fichier de plugin.
type Plugin struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Version     string   `yaml:"version"`
	Author      string   `yaml:"author"`
	CVEs        []string `yaml:"cves"`
	Product     string   `yaml:"product"`
	Description string   `yaml:"description"`
	Mode        string   `yaml:"mode"` // canary ou fingerprint
	Proof       string   `yaml:"proof"`
	Sent        string   `yaml:"sent"`
	Remediation []string `yaml:"remediation"`
	References  []string `yaml:"references"`
	Tags        []string `yaml:"tags"`
	DefaultPort int      `yaml:"default_port"`
	// LabValidated et LabNote décrivent la validation du plugin contre des cibles réelles.
	LabValidated bool   `yaml:"lab_validated"`
	LabNote      string `yaml:"lab_note"`

	Steps    []Step       `yaml:"steps"`
	Extract  []Extract    `yaml:"extract"`
	Matchers []Matcher    `yaml:"matchers"`
	Rule     *VersionRule `yaml:"version_rule"`
	// Fallback est le message « non concluant » quand aucun matcher ni règle ne s'applique.
	Fallback string     `yaml:"fallback_message"`
	Proofs   *ProofRule `yaml:"proofs"`
}

// Step est une étape : exactement un de HTTP ou TCP.
type Step struct {
	ID   string    `yaml:"id"`
	HTTP *HTTPStep `yaml:"http"`
	TCP  *TCPStep  `yaml:"tcp"`
	// When conditionne l'étape à une valeur déjà extraite (ou encore absente).
	When *When `yaml:"when"`
	// Points décrit chaque point de canari utilisé par l'étape (p1 : « en-tête User-Agent »).
	Points map[string]string `yaml:"points"`
}

// When est une condition sur les extractions déjà faites.
type When struct {
	Found   string `yaml:"found"`   // l'extraction nommée a une valeur
	Missing string `yaml:"missing"` // l'extraction nommée n'a pas (encore) de valeur
}

func (w *When) holds(extracted map[string]string) bool {
	if w == nil {
		return true
	}
	if w.Found != "" && extracted[w.Found] == "" {
		return false
	}
	if w.Missing != "" && extracted[w.Missing] != "" {
		return false
	}
	return true
}

// HTTPStep est une requête vers l'asset.
type HTTPStep struct {
	Method  string            `yaml:"method"`
	Path    string            `yaml:"path"` // relatif à l'URL cible ; vide = URL cible telle quelle
	Headers map[string]string `yaml:"headers"`
	Body    string            `yaml:"body"`
}

// TCPStep est un échange brut sur un port de l'asset.
type TCPStep struct {
	Port      int    `yaml:"port"` // vide = default_port, puis port de l'URL cible
	TLS       bool   `yaml:"tls"`
	Send      string `yaml:"send"`
	SendHex   string `yaml:"send_hex"`
	ReadBytes int    `yaml:"read_bytes"`
	Timeout   string `yaml:"timeout"`
}

// Extract capture une valeur dans la réponse d'une étape.
type Extract struct {
	Name   string `yaml:"name"`
	Step   string `yaml:"step"`
	Part   string `yaml:"part"` // body (défaut), header:<Nom>, status, all
	Regex  string `yaml:"regex"`
	Format string `yaml:"format"` // ex. "{1}.{2}" ; défaut : premier groupe
}

// Cond est une condition sur la réponse d'une étape.
type Cond struct {
	Step     string   `yaml:"step"`
	Part     string   `yaml:"part"`
	Status   []int    `yaml:"status"`
	Contains []string `yaml:"contains"` // au moins une (insensible à la casse)
	Regex    string   `yaml:"regex"`
}

// Matcher associe une ou plusieurs conditions (toutes requises) à un verdict (empreinte).
type Matcher struct {
	Cond    `yaml:",inline"`
	Also    []Cond `yaml:"also"` // conditions supplémentaires, sur d'autres étapes
	When    *When  `yaml:"when"`
	Verdict string `yaml:"verdict"` // probable, exposed, patched, inconclusive
	Message string `yaml:"message"`
}

// VersionRule compare une valeur extraite à des plages vulnérables.
type VersionRule struct {
	Var        string      `yaml:"var"`
	Vulnerable []RangeRule `yaml:"vulnerable"`
	Patched    string      `yaml:"patched_message"`
	Missing    string      `yaml:"missing_message"`
}

// RangeRule est une plage « >=8.5.1, <9.8.1 ».
type RangeRule struct {
	Range   string `yaml:"range"`
	Message string `yaml:"message"`
	Verdict string `yaml:"verdict"` // probable (défaut), patched, inconclusive, exposed
}

// ProofRule indique comment un plugin en mode canari prouve la faille.
type ProofRule struct {
	Callback       bool `yaml:"callback"`         // callback DNS/HTTP sur {{canary.dns.*}} / {{canary.url.*}}
	FileInResponse bool `yaml:"file_in_response"` // contenu du canari fichier relu dans une réponse
	FileCallback   bool `yaml:"file_callback"`    // contenu du canari fichier exfiltré par DNS/HTTP
}

var (
	idRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,62}$`)
	semverRe  = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	cveRe     = regexp.MustCompile(`^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]+|[A-Z][A-Za-z0-9 -]{2,40})$`)
	varRe     = regexp.MustCompile(`\{\{\s*([a-zA-Z0-9_.]+)\s*\}\}`)
	headerRe  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	pointRe   = regexp.MustCompile(`^p[0-9]{1,2}$`)
	verdicts  = map[string]bool{"probable": true, "exposed": true, "patched": true, "inconclusive": true}
	httpVerbs = map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "HEAD": true, "OPTIONS": true}
)

// Parse lit et valide un plugin. Les champs inconnus sont refusés.
func Parse(data []byte) (*Plugin, error) {
	if len(data) > MaxSize {
		return nil, fmt.Errorf("plugin trop volumineux (%d Kio au maximum)", MaxSize>>10)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var p Plugin
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("YAML invalide : %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// vars autorisées dans les gabarits, hors canari (vérifiées à part).
var targetVars = map[string]bool{
	"target.dir": true, "target.host": true, "target.port": true, "target.base": true, "target.path": true, "target.url": true, "random": true,
}

// checkTemplate vérifie les variables d'un gabarit et indique s'il utilise un canari réseau ou le fichier.
func checkTemplate(s string) (usesNet, usesFile bool, err error) {
	for _, m := range varRe.FindAllStringSubmatch(s, -1) {
		v := m[1]
		switch {
		case targetVars[v]:
		case v == "canary.file.path":
			usesFile = true
		case strings.HasPrefix(v, "canary.dns.") || strings.HasPrefix(v, "canary.url."):
			pt := v[len("canary.dns."):]
			if !pointRe.MatchString(pt) {
				return false, false, fmt.Errorf("point de canari invalide %q (p1 à p99)", pt)
			}
			usesNet = true
		default:
			return false, false, fmt.Errorf("variable inconnue {{%s}}", v)
		}
	}
	return usesNet, usesFile, nil
}

// Validate applique toutes les règles du format.
func (p *Plugin) Validate() error {
	var errs []string
	add := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	if !idRe.MatchString(p.ID) {
		add("id : minuscules, chiffres et tirets, 3 à 63 caractères")
	}
	if strings.TrimSpace(p.Name) == "" || len(p.Name) > 60 {
		add("name : obligatoire (60 caractères au maximum)")
	}
	if !semverRe.MatchString(p.Version) {
		add("version : format x.y.z")
	}
	if len(p.CVEs) == 0 {
		add("cves : au moins une référence")
	}
	for _, c := range p.CVEs {
		if !cveRe.MatchString(c) {
			add("cves : référence invalide %q", c)
		}
	}
	if strings.TrimSpace(p.Description) == "" || strings.TrimSpace(p.Sent) == "" {
		add("description et sent (ce qui est envoyé à la cible) sont obligatoires")
	}
	if len(p.Remediation) == 0 {
		add("remediation : au moins une mesure")
	}
	if p.DefaultPort < 0 || p.DefaultPort > 65535 {
		add("default_port invalide")
	}
	if len(p.Steps) == 0 || len(p.Steps) > maxSteps {
		add("steps : entre 1 et %d étapes", maxSteps)
	}
	ids := map[string]bool{}
	var usesNet, usesFile bool
	for i, st := range p.Steps {
		where := fmt.Sprintf("étape %d", i+1)
		if st.ID == "" || !regexp.MustCompile(`^[a-z0-9_-]{1,32}$`).MatchString(st.ID) {
			add("%s : id obligatoire (minuscules, chiffres, - et _)", where)
		} else if ids[st.ID] {
			add("%s : id %q en double", where, st.ID)
		}
		ids[st.ID] = true
		if (st.HTTP == nil) == (st.TCP == nil) {
			add("%s : exactement un bloc http ou tcp", where)
			continue
		}
		var tpls []string
		if h := st.HTTP; h != nil {
			if h.Method == "" {
				h.Method = "GET"
			}
			h.Method = strings.ToUpper(h.Method)
			if !httpVerbs[h.Method] {
				add("%s : méthode HTTP %q non prise en charge", where, h.Method)
			}
			// Le chemin est relatif à l'asset : ni schéma, ni hôte, ni « // ».
			rel := h.Path
			for _, pre := range []string{"{{target.path}}", "{{target.dir}}"} {
				if strings.HasPrefix(rel, pre) {
					rel = "/" + strings.TrimPrefix(strings.TrimPrefix(rel, pre), "/")
				}
			}
			if h.Path != "" && (!strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "//") || strings.Contains(h.Path, "://") || strings.ContainsAny(h.Path, " \r\n#")) {
				add("%s : path doit être un chemin relatif à l'asset commençant par /", where)
			}
			if len(h.Body) > maxBody {
				add("%s : corps trop long", where)
			}
			for k, v := range h.Headers {
				if !headerRe.MatchString(k) || strings.EqualFold(k, "Host") || strings.ContainsAny(v, "\r\n") {
					add("%s : en-tête %q interdit ou invalide", where, k)
				}
				tpls = append(tpls, v)
			}
			tpls = append(tpls, h.Path, h.Body)
		}
		if t := st.TCP; t != nil {
			if t.Port < 0 || t.Port > 65535 {
				add("%s : port invalide", where)
			}
			if t.SendHex != "" {
				if _, err := hex.DecodeString(strings.ReplaceAll(t.SendHex, " ", "")); err != nil {
					add("%s : send_hex n'est pas de l'hexadécimal", where)
				}
				if varRe.MatchString(t.SendHex) {
					add("%s : send_hex ne peut pas contenir de variable", where)
				}
			}
			if t.ReadBytes < 0 || t.ReadBytes > maxRead {
				add("%s : read_bytes entre 0 et %d", where, maxRead)
			}
			if t.Timeout != "" {
				d, err := time.ParseDuration(t.Timeout)
				if err != nil || d <= 0 || d > maxStepDelay {
					add("%s : timeout entre 1ms et 30s", where)
				}
			}
			tpls = append(tpls, t.Send)
		}
		for pt, label := range st.Points {
			if !pointRe.MatchString(pt) || strings.TrimSpace(label) == "" || len(label) > 80 {
				add("%s : points : clé p1 à p99 et libellé court requis", where)
			}
		}
		for _, s := range tpls {
			n, f, err := checkTemplate(s)
			if err != nil {
				add("%s : %v", where, err)
			}
			usesNet = usesNet || n
			usesFile = usesFile || f
		}
	}
	for i, e := range p.Extract {
		if !regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`).MatchString(e.Name) || !ids[e.Step] {
			add("extract %d : name valide et step existant requis", i+1)
		}
		if _, err := regexp.Compile(e.Regex); err != nil || e.Regex == "" {
			add("extract %d : regex invalide", i+1)
		}
		if !validPart(e.Part) {
			add("extract %d : part invalide (body, status, all, header:<Nom>)", i+1)
		}
	}
	names := map[string]bool{}
	for _, e := range p.Extract {
		names[e.Name] = true
	}
	checkWhen := func(w *When, where string) {
		if w == nil {
			return
		}
		if (w.Found == "") == (w.Missing == "") || !names[w.Found+w.Missing] {
			add("%s : when doit désigner une extraction existante (found ou missing)", where)
		}
	}
	for i, st := range p.Steps {
		checkWhen(st.When, fmt.Sprintf("étape %d", i+1))
	}
	checkCond := func(c Cond, where string) {
		if !ids[c.Step] {
			add("%s : step existant requis", where)
		}
		if c.Regex != "" {
			if _, err := regexp.Compile(c.Regex); err != nil {
				add("%s : regex invalide", where)
			}
		}
		if len(c.Status) == 0 && len(c.Contains) == 0 && c.Regex == "" {
			add("%s : au moins une condition (status, contains ou regex)", where)
		}
		if !validPart(c.Part) {
			add("%s : part invalide", where)
		}
	}
	for i, m := range p.Matchers {
		where := fmt.Sprintf("matcher %d", i+1)
		if !verdicts[m.Verdict] {
			add("%s : verdict (probable, exposed, patched, inconclusive) requis", where)
		}
		checkCond(m.Cond, where)
		for j, c := range m.Also {
			checkCond(c, fmt.Sprintf("%s, also %d", where, j+1))
		}
		checkWhen(m.When, where)
	}
	if r := p.Rule; r != nil {
		found := false
		for _, e := range p.Extract {
			found = found || e.Name == r.Var
		}
		if !found || len(r.Vulnerable) == 0 {
			add("version_rule : var doit désigner une extraction et vulnerable contenir au moins une plage")
		}
		for _, rr := range r.Vulnerable {
			if _, err := parseRange(rr.Range); err != nil {
				add("version_rule : %v", err)
			}
			if rr.Verdict != "" && !verdicts[rr.Verdict] {
				add("version_rule : verdict de plage invalide %q", rr.Verdict)
			}
		}
	}
	switch p.Mode {
	case "canary":
		pr := p.Proofs
		if pr == nil || !(pr.Callback || pr.FileInResponse || pr.FileCallback) {
			add("mode canary : proofs doit activer callback, file_in_response ou file_callback")
		} else {
			if pr.Callback && !usesNet {
				add("proofs.callback : aucune étape n'utilise {{canary.dns.pN}} ou {{canary.url.pN}}")
			}
			if (pr.FileInResponse || pr.FileCallback) && !usesFile {
				add("proofs.file_* : aucune étape n'utilise {{canary.file.path}}")
			}
		}
		if p.Rule != nil || len(p.Matchers) > 0 {
			add("mode canary : version_rule et matchers sont réservés au mode fingerprint")
		}
	case "fingerprint":
		if usesNet || usesFile {
			add("mode fingerprint : aucune variable de canari autorisée (aucune charge)")
		}
		if p.Proofs != nil {
			add("mode fingerprint : proofs est réservé au mode canary")
		}
		if p.Rule == nil && len(p.Matchers) == 0 {
			add("mode fingerprint : version_rule ou matchers requis")
		}
	default:
		add("mode : canary ou fingerprint")
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, " ; "))
	}
	return nil
}

func validPart(p string) bool {
	return p == "" || p == "body" || p == "status" || p == "all" || strings.HasPrefix(p, "header:") && headerRe.MatchString(p[7:])
}

// RequiresFileCanary indique si le plugin utilise le canari fichier.
func (p *Plugin) RequiresFileCanary() bool {
	return p.Proofs != nil && (p.Proofs.FileInResponse || p.Proofs.FileCallback)
}

// UsesTCP indique si le plugin contient des étapes TCP.
func (p *Plugin) UsesTCP() bool {
	for _, s := range p.Steps {
		if s.TCP != nil {
			return true
		}
	}
	return false
}
