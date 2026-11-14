// Package checks définit l'interface des checkers et leur registre. Les checkers eux-mêmes sont
// des plugins (package plugin), préinstallés pour les plugins officiels.
//
// Règles communes à tous les checkers :
//   - un checker ne reçoit que l'URL cible, les canaris et des connexions confinées à l'asset ;
//     aucun contenu fourni par l'utilisateur n'entre dans un payload ;
//   - en mode « canary », le seul effet recherché sur la cible est de toucher un canari : résolution
//     DNS ou appel HTTP vers le récepteur, ou relecture du canari fichier déposé sur l'asset ;
//   - en mode « fingerprint », aucune charge n'est envoyée : seule l'empreinte publique (en-têtes,
//     pages d'accueil) est lue et comparée aux versions corrigées.
package checks

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"sync"
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
	// Source : « builtin » (compilé dans OpenCVEC) ou « plugin » (importé et signé).
	Source    string `json:"source"`
	Version   string `json:"version,omitempty"`
	Publisher string `json:"publisher,omitempty"`
	Signed    bool   `json:"signed"`
	// RequiresFileCanary : le check exige un canari fichier déposé sur l'asset.
	RequiresFileCanary bool `json:"requires_file_canary"`
	// FileCallback : le contenu du canari fichier peut revenir par DNS/HTTP (exfiltration par la cible).
	FileCallback bool `json:"file_callback"`
}

// FileCanary est le canari fichier déposé par l'entreprise sur l'asset.
type FileCanary struct {
	Path  string
	Token string
}

// Env est tout ce qu'un checker reçoit.
type Env struct {
	// Client est confiné au périmètre de l'asset (voir netguard).
	Client *http.Client
	// CanaryHost renvoie le nom à faire résoudre pour un point d'injection (p1, p2…).
	// Nil pour un checker d'empreinte.
	CanaryHost func(point string) string
	// File est le canari fichier de l'asset (nil s'il n'est pas déposé).
	File *FileCanary
	// Dial ouvre une connexion TCP confinée au périmètre de l'asset (étapes TCP des plugins).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
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

var (
	regMu    sync.RWMutex
	registry = map[string]Checker{}
	builtins = map[string]bool{}
)

func register(c Checker) {
	regMu.Lock()
	defer regMu.Unlock()
	registry[c.Info().ID] = c
	builtins[c.Info().ID] = true
}

// IsBuiltin indique si un identifiant est réservé par un checker compilé.
func IsBuiltin(id string) bool {
	regMu.RLock()
	defer regMu.RUnlock()
	return builtins[id]
}

// Register ajoute ou remplace un checker de plugin ; un identifiant réservé est refusé.
func Register(c Checker) error {
	regMu.Lock()
	defer regMu.Unlock()
	id := c.Info().ID
	if builtins[id] {
		return fmt.Errorf("l'identifiant %q est réservé par un checker intégré", id)
	}
	registry[id] = c
	return nil
}

// Unregister retire un checker de plugin.
func Unregister(id string) {
	regMu.Lock()
	defer regMu.Unlock()
	if !builtins[id] {
		delete(registry, id)
	}
}

// Get renvoie un checker par identifiant.
func Get(id string) (Checker, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	c, ok := registry[id]
	return c, ok
}

// All renvoie le catalogue trié (canari d'abord, puis par nom).
func All() []Info {
	regMu.RLock()
	out := make([]Info, 0, len(registry))
	for _, c := range registry {
		i := c.Info()
		if i.Source == "" {
			i.Source = "builtin"
		}
		out = append(out, i)
	}
	regMu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Mode != out[j].Mode {
			return out[i].Mode == ModeCanary
		}
		return out[i].Name < out[j].Name
	})
	return out
}
