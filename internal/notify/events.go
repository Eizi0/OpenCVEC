package notify

import (
	"context"
	"fmt"
	"time"

	"github.com/Eizi0/OpenCVEC/internal/checks"
)

// Verdict notifie un verdict prouvé, probable ou exposé (branché sur runner.OnVerdict).
func (n *Notifier) Verdict(checkID int64, verdict, summary string) {
	if n == nil || n.DB == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var host, checker string
	_ = n.DB.QueryRow(ctx, `SELECT a.host, k.checker FROM checks k JOIN assets a ON a.id = k.asset_id WHERE k.id = $1`, checkID).Scan(&host, &checker)
	if c, ok := checks.Get(checker); ok {
		checker = c.Info().Name
	}
	kind, label := KindProbable, map[string]string{"probable": "Probable", "exposed": "Exposé"}[verdict]
	if verdict == checks.VerdictProved {
		kind, label = KindProved, "Vulnérabilité prouvée"
	}
	n.Send(Event{Kind: kind, Title: fmt.Sprintf("%s : %s sur %s", label, checker, host), Text: summary, Link: fmt.Sprintf("/checks/%d", checkID)})
}

// Honeytoken notifie la lecture d'un canari fichier hors d'un check.
func (n *Notifier) Honeytoken(host, text string) {
	n.Send(Event{Kind: KindHoneytoken, Title: "Canari fichier lu hors check : " + host, Text: text, Link: "/callbacks"})
}
