package report

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
)

var verdictRGB = map[string][3]int{
	"proved": {179, 38, 30}, "probable": {107, 63, 179}, "exposed": {107, 63, 179},
	"patched": {31, 111, 67}, "inconclusive": {90, 100, 114}, "error": {90, 100, 114},
}

// PDF rend le rapport en document PDF autonome (polices standard, encodage Windows-1252).
func (r Report) PDF() ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	tr := pdf.UnicodeTranslatorFromDescriptor("")
	// Caractères absents de Windows-1252 remplacés avant traduction.
	clean := strings.NewReplacer("≠", "!=", "→", "->", "Δ", "delta ", "✓", "v", "•", "-", " ", " ", " ", " ")
	t := func(s string) string { return tr(clean.Replace(s)) }
	pdf.SetTitle(t(r.Title), true)
	pdf.SetCreator("OpenCVEC", true)
	pdf.SetMargins(16, 16, 16)
	pdf.SetAutoPageBreak(true, 16)
	pdf.SetFooterFunc(func() {
		pdf.SetY(-12)
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(120, 120, 120)
		pdf.CellFormat(0, 6, t(fmt.Sprintf("OpenCVEC · %s · page %d/{nb}", r.Title, pdf.PageNo())), "", 0, "C", false, 0, "")
	})
	pdf.AliasNbPages("")
	pdf.AddPage()
	w, _ := pdf.GetPageSize()
	width := w - 32

	pdf.SetFont("Helvetica", "B", 18)
	pdf.SetTextColor(20, 23, 28)
	pdf.MultiCell(width, 8, t(r.Title), "", "L", false)
	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(90, 100, 114)
	pdf.MultiCell(width, 5, t(fmt.Sprintf("Périmètre : %s · généré le %s par %s · zone canari %s",
		r.Scope, r.GeneratedAt.UTC().Format("02/01/2006 15:04 UTC"), r.GeneratedBy, r.CanaryZone)), "", "L", false)
	pdf.Ln(3)

	// Synthèse.
	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetTextColor(20, 23, 28)
	for _, c := range []struct {
		n     int
		label string
	}{{r.Counts.Proved, "prouvé(s)"}, {r.Counts.Probable, "probable(s)"}, {r.Counts.Exposed, "exposé(s)"}, {r.Counts.Patched, "corrigé(s)"}, {r.Counts.Inconclusive, "non concluant(s)"}} {
		pdf.CellFormat(width/5, 9, t(fmt.Sprintf("%d %s", c.n, c.label)), "1", 0, "C", false, 0, "")
	}
	pdf.Ln(12)
	pdf.SetFont("Helvetica", "", 8.5)
	pdf.SetTextColor(90, 100, 114)
	pdf.MultiCell(width, 4.5, t("« Prouvé » : la cible a résolu un canari à usage unique, signé pour cet asset et ce check, ou relu le canari fichier déposé sur l'asset. « Probable » : version exposée dans une plage vulnérable, sans preuve active. Aucun payload n'exécute de commande ni n'écrit sur la cible."), "", "L", false)
	pdf.Ln(2)

	if len(r.Items) == 0 {
		pdf.SetFont("Helvetica", "", 10)
		pdf.MultiCell(width, 6, t("Aucun check dans ce périmètre."), "", "L", false)
	}
	kv := func(k, v string) {
		if v == "" {
			return
		}
		pdf.SetFont("Helvetica", "", 8.5)
		pdf.SetTextColor(90, 100, 114)
		pdf.CellFormat(42, 5, t(k), "", 0, "L", false, 0, "")
		pdf.SetTextColor(20, 23, 28)
		pdf.MultiCell(width-42, 5, t(v), "", "L", false)
	}
	date := func(d *time.Time) string {
		if d == nil {
			return "—"
		}
		return d.UTC().Format("02/01/2006 15:04:05 UTC")
	}
	for _, it := range r.Items {
		pdf.Ln(4)
		if _, y := pdf.GetXY(); y > 240 {
			pdf.AddPage()
		}
		pdf.SetDrawColor(210, 214, 220)
		x, y := pdf.GetXY()
		pdf.Line(x, y, x+width, y)
		pdf.Ln(2)
		pdf.SetFont("Helvetica", "B", 12)
		pdf.SetTextColor(20, 23, 28)
		pdf.MultiCell(width, 6, t(it.Checker+" · "+it.Asset), "", "L", false)
		rgb := verdictRGB[it.Verdict]
		pdf.SetTextColor(rgb[0], rgb[1], rgb[2])
		pdf.SetFont("Helvetica", "B", 10)
		pdf.CellFormat(0, 6, t(verdictLabel[it.Verdict]+"   ·   "+strings.Join(it.CVEs, ", ")), "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 9.5)
		pdf.SetTextColor(20, 23, 28)
		pdf.MultiCell(width, 5, t(it.Summary), "", "L", false)
		pdf.Ln(1)
		kv("URL cible", it.TargetURL)
		kv("Mode", map[bool]string{true: "preuve par canari", false: "empreinte (aucune charge)"}[it.Mode == "canary"])
		kv("Canari", it.Canary)
		kv("Envoi", date(it.SentAt))
		kv("Verdict rendu", date(it.FinishedAt))
		kv("Ce qui a été envoyé", it.Sent)
		for k, v := range it.Evidence {
			kv(k, v)
		}
		if len(it.Callbacks) > 0 {
			pdf.Ln(1)
			pdf.SetFont("Helvetica", "B", 9)
			pdf.CellFormat(0, 6, t("Callbacks reçus"), "", 1, "L", false, 0, "")
			pdf.SetFont("Helvetica", "", 8)
			for _, cb := range it.Callbacks {
				src := cb.SourceIP
				if cb.SourceMatches {
					src += " (IP de l'asset)"
				}
				pdf.MultiCell(width, 4.5, t(fmt.Sprintf("%s · %s %s · %s · %s · %s", cb.ReceivedAt.UTC().Format("02/01 15:04:05.000"),
					cb.Proto, cb.QType, cb.QName, src, statusLabel[cb.Status])), "", "L", false)
				if cb.Raw != "" {
					raw := cb.Raw
					if len(raw) > 1200 {
						raw = raw[:1200] + "…"
					}
					pdf.SetFont("Courier", "", 7)
					pdf.SetTextColor(70, 76, 86)
					pdf.MultiCell(width, 3.6, t(raw), "", "L", false)
					pdf.SetFont("Helvetica", "", 8)
					pdf.SetTextColor(20, 23, 28)
				}
			}
		}
		if len(it.Remediation) > 0 {
			pdf.Ln(1)
			pdf.SetFont("Helvetica", "B", 9)
			pdf.CellFormat(0, 6, t("Remédiation"), "", 1, "L", false, 0, "")
			pdf.SetFont("Helvetica", "", 8.5)
			for i, rem := range it.Remediation {
				pdf.MultiCell(width, 4.6, t(fmt.Sprintf("%d. %s", i+1, rem)), "", "L", false)
			}
		}
	}
	pdf.Ln(6)
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetTextColor(120, 120, 120)
	pdf.MultiCell(width, 4, t("Rapport OpenCVEC. L'empreinte SHA-256 de ce fichier est enregistrée dans l'instance au moment de sa génération."), "", "L", false)

	var b bytes.Buffer
	if err := pdf.Output(&b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
