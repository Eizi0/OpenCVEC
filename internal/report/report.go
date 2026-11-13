// Package report produit les rapports de vérification (HTML imprimable et JSON).
package report

import (
	"bytes"
	"encoding/json"
	"html/template"
	"time"
)

// Callback est une preuve de callback incluse dans le rapport.
type Callback struct {
	ReceivedAt    time.Time `json:"received_at"`
	Proto         string    `json:"proto"`
	QType         string    `json:"qtype"`
	QName         string    `json:"qname"`
	Point         string    `json:"point"`
	SourceIP      string    `json:"source_ip"`
	SourceMatches bool      `json:"source_matches"`
	Status        string    `json:"status"`
	Raw           string    `json:"raw,omitempty"`
}

// Item est un check du rapport.
type Item struct {
	CheckID     int64             `json:"check_id"`
	CampaignID  int64             `json:"campaign_id"`
	Asset       string            `json:"asset"`
	TargetURL   string            `json:"target_url"`
	Checker     string            `json:"checker"`
	CVEs        []string          `json:"cves"`
	Mode        string            `json:"mode"`
	Verdict     string            `json:"verdict"`
	Summary     string            `json:"summary"`
	SentAt      *time.Time        `json:"sent_at,omitempty"`
	FinishedAt  *time.Time        `json:"finished_at,omitempty"`
	Canary      string            `json:"canary,omitempty"`
	Evidence    map[string]string `json:"evidence,omitempty"`
	Sent        string            `json:"payload_description"`
	Remediation []string          `json:"remediation"`
	Callbacks   []Callback        `json:"callbacks,omitempty"`
}

// Report est le contenu d'un rapport.
type Report struct {
	Title       string    `json:"title"`
	Scope       string    `json:"scope"`
	GeneratedAt time.Time `json:"generated_at"`
	GeneratedBy string    `json:"generated_by"`
	CanaryZone  string    `json:"canary_zone"`
	Counts      Counts    `json:"counts"`
	Items       []Item    `json:"items"`
}

// Counts résume les verdicts.
type Counts struct {
	Proved, Probable, Exposed, Patched, Inconclusive, Error int
}

// Summary renvoie le résumé d'une ligne.
func (c Counts) Summary() string {
	parts := []string{}
	add := func(n int, one, many string) {
		if n == 1 {
			parts = append(parts, "1 "+one)
		} else if n > 1 {
			parts = append(parts, itoa(n)+" "+many)
		}
	}
	add(c.Proved, "prouvé", "prouvés")
	add(c.Probable, "probable", "probables")
	add(c.Exposed, "exposé", "exposés")
	add(c.Patched, "corrigé", "corrigés")
	add(c.Inconclusive, "non concluant", "non concluants")
	add(c.Error, "en erreur", "en erreur")
	if len(parts) == 0 {
		return "aucun check"
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += " · " + p
	}
	return out
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// Count calcule les totaux.
func (r *Report) Count() {
	r.Counts = Counts{}
	for _, it := range r.Items {
		switch it.Verdict {
		case "proved":
			r.Counts.Proved++
		case "probable":
			r.Counts.Probable++
		case "exposed":
			r.Counts.Exposed++
		case "patched":
			r.Counts.Patched++
		case "inconclusive":
			r.Counts.Inconclusive++
		default:
			r.Counts.Error++
		}
	}
}

// JSON sérialise le rapport.
func (r Report) JSON() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

var verdictLabel = map[string]string{
	"proved": "Prouvé vulnérable", "probable": "Probable", "exposed": "Exposé",
	"patched": "Version corrigée", "inconclusive": "Non concluant", "error": "Erreur",
}

var statusLabel = map[string]string{
	"correlated": "Corrélé", "duplicate": "Doublon", "expired": "Expiré", "replay": "Rejeu", "unknown": "Inconnu",
}

var tpl = template.Must(template.New("r").Funcs(template.FuncMap{
	"verdict": func(v string) string { return verdictLabel[v] },
	"status":  func(v string) string { return statusLabel[v] },
	"date": func(t any) string {
		switch x := t.(type) {
		case time.Time:
			return x.UTC().Format("02/01/2006 15:04:05 UTC")
		case *time.Time:
			if x == nil {
				return "—"
			}
			return x.UTC().Format("02/01/2006 15:04:05.000 UTC")
		}
		return ""
	},
}).Parse(`<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><title>{{.Title}}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root{--ink:#14171c;--muted:#5a6472;--line:#d9dee5;--proved:#b3261e;--prob:#6b3fb3;--ok:#1f6f43}
body{font:14px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--ink);margin:0;background:#fff}
main{max-width:920px;margin:0 auto;padding:40px 28px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:28px 0 8px}h3{font-size:15px;margin:16px 0 6px}
.meta{color:var(--muted);font-size:13px}.box{border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:14px 0;break-inside:avoid}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-weight:600;font-size:12px;border:1px solid currentColor}
.proved{color:var(--proved)}.probable,.exposed{color:var(--prob)}.patched{color:var(--ok)}.inconclusive,.error{color:var(--muted)}
dl{display:grid;grid-template-columns:180px 1fr;gap:4px 14px;margin:8px 0}dt{color:var(--muted)}dd{margin:0;word-break:break-word}
code,pre{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}pre{background:#f5f7fa;border:1px solid var(--line);border-radius:8px;padding:10px;white-space:pre-wrap;word-break:break-all}
table{border-collapse:collapse;width:100%;font-size:13px}td,th{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
.summary{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}.summary div{border:1px solid var(--line);border-radius:8px;padding:8px 14px}
footer{margin-top:32px;color:var(--muted);font-size:12px}
@media print{main{padding:0}.box{border-color:#bbb}}
</style></head><body><main>
<h1>{{.Title}}</h1>
<div class="meta">Périmètre : {{.Scope}} · généré le {{date .GeneratedAt}} par {{.GeneratedBy}} · zone canari {{.CanaryZone}}</div>
<div class="summary">
<div><strong>{{.Counts.Proved}}</strong> prouvé(s)</div><div><strong>{{.Counts.Probable}}</strong> probable(s)</div>
<div><strong>{{.Counts.Exposed}}</strong> exposé(s)</div><div><strong>{{.Counts.Patched}}</strong> corrigé(s)</div>
<div><strong>{{.Counts.Inconclusive}}</strong> non concluant(s)</div>
</div>
<p class="meta">« Prouvé » : la cible a résolu un canari à usage unique, signé pour cet asset et ce check. « Probable » : version exposée dans une plage vulnérable, sans preuve active. Aucun payload n'exécute de commande ni n'écrit sur la cible.</p>
{{range .Items}}
<section class="box">
<h2 style="margin-top:0">{{.Checker}} · {{.Asset}} <span class="pill {{.Verdict}}">{{verdict .Verdict}}</span></h2>
<div class="meta">{{range $i, $c := .CVEs}}{{if $i}}, {{end}}{{$c}}{{end}} · check #{{.CheckID}} · campagne #{{.CampaignID}}</div>
<p>{{.Summary}}</p>
<dl>
<dt>URL cible</dt><dd><code>{{.TargetURL}}</code></dd>
<dt>Mode</dt><dd>{{if eq .Mode "canary"}}preuve par canari{{else}}empreinte (aucune charge){{end}}</dd>
{{if .Canary}}<dt>Canari</dt><dd><code>{{.Canary}}</code></dd>{{end}}
<dt>Envoi</dt><dd>{{date .SentAt}}</dd><dt>Verdict rendu</dt><dd>{{date .FinishedAt}}</dd>
<dt>Ce qui a été envoyé</dt><dd>{{.Sent}}</dd>
{{range $k, $v := .Evidence}}<dt>{{$k}}</dt><dd>{{$v}}</dd>{{end}}
</dl>
{{if .Callbacks}}<h3>Callbacks reçus</h3>
<table><tr><th>Reçu</th><th>Type</th><th>Nom</th><th>Source</th><th>Statut</th></tr>
{{range .Callbacks}}<tr><td>{{date .ReceivedAt}}</td><td>{{.Proto}} {{.QType}}</td><td><code>{{.QName}}</code></td><td><code>{{.SourceIP}}</code>{{if .SourceMatches}} (IP de l'asset){{end}}</td><td>{{status .Status}}</td></tr>{{end}}
</table>
{{range .Callbacks}}{{if .Raw}}<pre>{{.Raw}}</pre>{{end}}{{end}}{{end}}
{{if .Remediation}}<h3>Remédiation</h3><ol>{{range .Remediation}}<li>{{.}}</li>{{end}}</ol>{{end}}
</section>
{{else}}<p>Aucun check dans ce périmètre.</p>{{end}}
<footer>Rapport OpenCVEC. L'empreinte SHA-256 de ce fichier est enregistrée dans l'instance au moment de sa génération.</footer>
</main></body></html>`))

// HTML rend le rapport en page autonome imprimable.
func (r Report) HTML() ([]byte, error) {
	var b bytes.Buffer
	err := tpl.Execute(&b, r)
	return b.Bytes(), err
}
