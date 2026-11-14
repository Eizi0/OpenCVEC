package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNotificationsOnProofAndSettings(t *testing.T) {
	e := newEnv(t)
	admin := e.login("admin@test")
	var mu sync.Mutex
	var events []map[string]any
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		mu.Lock()
		events = append(events, m)
		mu.Unlock()
	}))
	defer hook.Close()
	cfg := map[string]any{"webhook_url": hook.URL, "webhook_format": "json", "smtp_security": "starttls", "smtp_port": 587,
		"smtp_host": "smtp.exemple.fr", "smtp_from": "opencvec@exemple.fr", "smtp_user": "u", "smtp_password": "secret-smtp",
		"on_honeytoken": true, "on_proved": true, "on_probable": false, "on_schedule": true}
	admin.json("PUT", "/api/settings/notifications", cfg, nil, 200)
	var got map[string]any
	admin.json("GET", "/api/settings/notifications", nil, &got, 200)
	if got["smtp_password"] != keepSecret {
		t.Fatalf("le mot de passe SMTP ne doit jamais être renvoyé : %v", got["smtp_password"])
	}
	var raw string
	_ = e.db.QueryRow(t.Context(), `SELECT value->>'smtp_password' FROM settings WHERE key = 'notifications'`).Scan(&raw)
	if raw == "secret-smtp" {
		t.Log("secrets.Box sans clé en test : stockage en clair attendu dans ce cas")
	}
	// Garder le mot de passe : le marqueur ne doit pas l'écraser.
	cfg["smtp_password"] = keepSecret
	admin.json("PUT", "/api/settings/notifications", cfg, nil, 200)
	_ = e.db.QueryRow(t.Context(), `SELECT value->>'smtp_password' FROM settings WHERE key = 'notifications'`).Scan(&raw)
	if raw != "secret-smtp" {
		t.Fatalf("mot de passe SMTP perdu : %q", raw)
	}
	// Test d'envoi (le webhook seul : pas d'e-mail pour éviter le réseau).
	delete(cfg, "smtp_host")
	cfg["email_to"] = ""
	var res map[string]string
	admin.json("POST", "/api/settings/notifications/test", cfg, &res, 200)
	if res["webhook"] != "ok" {
		t.Fatalf("test du webhook : %v", res)
	}
	admin.json("PUT", "/api/settings/notifications", cfg, nil, 200)

	// Une vulnérabilité prouvée est notifiée.
	assetID := e.ownedLoopbackAsset(admin)
	vuln := e.vulnerable()
	var c struct{ ID int64 }
	admin.json("POST", "/api/campaigns", map[string]any{"asset_id": assetID, "target_url": vuln.URL + "/", "checkers": []string{"log4shell"}}, &c, 201)
	admin.waitCampaign(c.ID)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(events)
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) < 2 || events[0]["event"] != "test" || events[1]["event"] != "proved" ||
		!strings.Contains(events[1]["title"].(string), "Log4JChecker sur 127.0.0.1") || !strings.HasPrefix(events[1]["url"].(string), "https://opencvec.test/checks/") {
		t.Fatalf("événements reçus : %v", events)
	}
}
