// Package checks contient les checkers de CVE.
//
// Règles communes à tous les modules :
//   - un checker ne reçoit que l'URL cible et une fonction qui fabrique les noms d'hôte du canari ;
//     aucun contenu fourni par l'utilisateur n'entre dans un payload ;
//   - en mode « canary », le seul effet recherché sur la cible est une résolution DNS (ou un appel
//     HTTP) vers le canari : pas de commande, pas d'écriture, pas d'exfiltration ;
//   - en mode « fingerprint », aucune charge n'est envoyée : seule l'empreinte publique (en-têtes,
//     pages d'accueil) est lue et comparée aux versions corrigées.
package checks

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// Mode d'un checker.
const (
	ModeCanary      = "canary"
	ModeFingerprint = "fingerprint"
)

// Verdicts possibles d'un check.
const (
	VerdictProved       = "proved"       // canari déclenché par la cible
	VerdictProbable     = "probable"     // version exposée dans une plage vulnérable
	VerdictExposed      = "exposed"      // surface d'attaque exposée (sans CVE prouvée)
	VerdictPatched      = "patched"      // version exposée corrigée
	VerdictInconclusive = "inconclusive" // pas de callback, ou empreinte absente
	VerdictError        = "error"
)

// Info décrit un checker dans le catalogue.
type Info struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	CVEs        []string `json:"cves"`
	Product     string   `json:"product"`
	Mode        string   `json:"mode"`
	Description string   `json:"description"`
	Proof       string   `json:"proof"`
	Sent        string   `json:"sent"`
	Remediation []string `json:"remediation"`
	References  []string `json:"references"`
	Tags        []string `json:"tags"`
	// LabValidated indique que le module a été validé contre une cible réelle du labo (lab/).
	LabValidated bool   `json:"lab_validated"`
	LabNote      string `json:"lab_note"`
}

// Env est tout ce qu'un checker reçoit.
type Env struct {
	// Client est confiné au périmètre de l'asset (voir netguard).
	Client *http.Client
	// CanaryHost renvoie le nom à faire résoudre pour un point d'injection (p1, p2…).
	// Nil pour un checker d'empreinte.
	CanaryHost func(point string) string
}

// Outcome est le résultat d'exécution d'un checker.
type Outcome struct {
	// Verdict direct (empreinte). Vide en mode canari : le verdict dépend du callback.
	Verdict string `json:"verdict,omitempty"`
	Summary string `json:"summary"`
	// Points liste les points d'injection utilisés (canari) ; Evidence, les observations.
	Points   []Point           `json:"points,omitempty"`
	Evidence map[string]string `json:"evidence,omitempty"`
}

// Point est un point d'injection.
type Point struct {
	ID       string `json:"id"`
	Location string `json:"location"`
	Status   int    `json:"status,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Checker est implémenté par chaque module.
type Checker interface {
	Info() Info
	Run(ctx context.Context, target string, env Env) (Outcome, error)
}

var registry = map[string]Checker{}

func register(c Checker) { registry[c.Info().ID] = c }

// Get renvoie un checker par identifiant.
func Get(id string) (Checker, bool) {
	c, ok := registry[id]
	return c, ok
}

// All renvoie le catalogue trié (canari d'abord, puis par nom).
func All() []Info {
	out := make([]Info, 0, len(registry))
	for _, c := range registry {
		out = append(out, c.Info())
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Mode != out[j].Mode {
			return out[i].Mode == ModeCanary
		}
		return out[i].Name < out[j].Name
	})
	return out
}

const userAgent = "OpenCVEC/0.1 (+verification de vulnerabilite autorisee)"

// send exécute une requête et lit au plus 256 Kio de réponse.
func send(ctx context.Context, c *http.Client, req *http.Request) (*http.Response, []byte, error) {
	req = req.WithContext(ctx)
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", userAgent)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return resp, b, nil
}

func joinURL(base, p string) string {
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(p, "/")
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	// Une *url.Error répète l'URL complète (avec les payloads) : seule la cause est utile.
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	s := err.Error()
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// anySent indique si au moins une requête est partie (sinon le check est en erreur).
func anySent(ps []Point) bool {
	for _, p := range ps {
		if p.Error == "" {
			return true
		}
	}
	return false
}
