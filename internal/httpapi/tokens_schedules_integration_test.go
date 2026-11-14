package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func (e *env) withToken(tok, method, path string, body any) (int, string) {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.api.URL+path, r)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestAPITokens(t *testing.T) {
	e := newEnv(t)
	analyst := e.login("analyste@test")
	var created struct{ Token string }
	analyst.json("POST", "/api/me/tokens", map[string]any{"name": "CI nocturne", "expires_days": 30}, &created, 201)
	if !strings.HasPrefix(created.Token, "ocv_") {
		t.Fatalf("jeton : %q", created.Token)
	}
	// Le jeton donne les droits de son propriétaire, sans en-tête CSRF.
	if st, _ := e.withToken(created.Token, "GET", "/api/assets", nil); st != 200 {
		t.Fatalf("lecture avec jeton : %d", st)
	}
	if st, _ := e.withToken(created.Token, "POST", "/api/assets", map[string]any{"host": "api.exemple.fr", "proof_method": "dns_txt"}); st != 201 {
		t.Fatalf("écriture analyste avec jeton : %d", st)
	}
	if st, _ := e.withToken(created.Token, "GET", "/api/users", nil); st != 403 {
		t.Fatalf("un jeton d'analyste ne doit pas accéder à l'administration : %d", st)
	}
	// Un jeton ne peut pas gérer les jetons ni changer le mot de passe.
	if st, _ := e.withToken(created.Token, "POST", "/api/me/tokens", map[string]any{"name": "x"}); st != 403 {
		t.Fatalf("création de jeton par jeton : %d", st)
	}
	if st, _ := e.withToken(created.Token, "POST", "/api/me/password", map[string]any{"current": "motdepasse-solide", "new": "nouveau-mot-de-passe"}); st != 403 {
		t.Fatalf("changement de mot de passe par jeton : %d", st)
	}
	// Seule l'empreinte est stockée.
	var n int
	_ = e.db.QueryRow(context.Background(), `SELECT count(*) FROM api_tokens WHERE prefix = $1 AND token_hash <> $2::bytea`, created.Token[:10], []byte(created.Token)).Scan(&n)
	if n != 1 {
		t.Fatal("le jeton doit être stocké sous forme d'empreinte")
	}
	// Révocation.
	var list []tokenRow
	analyst.json("GET", "/api/me/tokens", nil, &list, 200)
	if len(list) != 1 || list[0].LastUsedAt == nil {
		t.Fatalf("liste : %+v", list)
	}
	analyst.json("DELETE", "/api/me/tokens/"+itoa(list[0].ID), nil, nil, 200)
	if st, _ := e.withToken(created.Token, "GET", "/api/assets", nil); st != 401 {
		t.Fatalf("jeton révoqué accepté : %d", st)
	}
	if st, _ := e.withToken("ocv_inventé", "GET", "/api/assets", nil); st != 401 {
		t.Fatalf("jeton inventé accepté : %d", st)
	}
}

func TestSchedules(t *testing.T) {
	e := newEnv(t)
	admin := e.login("admin@test")
	analyst := e.login("analyste@test")
	assetID := e.ownedLoopbackAsset(admin)
	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("X-Powered-By", "PHP/8.3.20") }))
	defer safe.Close()
	if st, _ := analyst.do("POST", "/api/schedules", map[string]any{"asset_id": assetID, "target_url": "http://10.9.9.9/", "checkers": []string{"php2shell"}, "every_days": 30}); st != 400 {
		t.Fatalf("programmation hors périmètre acceptée : %d", st)
	}
	var sc struct{ ID int64 }
	analyst.json("POST", "/api/schedules", map[string]any{"asset_id": assetID, "target_url": safe.URL, "checkers": []string{"php2shell"}, "every_days": 30}, &sc, 201)

	// Échéance atteinte : une campagne est lancée au nom de l'analyste.
	e.srv.RunDueSchedules(context.Background(), time.Now().Add(time.Minute))
	var list []scheduleRow
	analyst.json("GET", "/api/schedules", nil, &list, 200)
	if len(list) != 1 || list[0].LastCampaignID == nil || list[0].LastError != "" || list[0].NextRunAt.Before(time.Now().Add(29*24*time.Hour)) {
		t.Fatalf("après exécution : %+v", list[0])
	}
	camp := analyst.waitCampaign(*list[0].LastCampaignID)
	if camp.Checks[0].Verdict != "probable" || camp.CreatedBy != "analyste@test" {
		t.Fatalf("campagne programmée : %+v", camp)
	}
	// Pas encore échu : rien n'est relancé.
	e.srv.RunDueSchedules(context.Background(), time.Now().Add(time.Hour))
	var n int
	_ = e.db.QueryRow(context.Background(), `SELECT count(*) FROM campaigns`).Scan(&n)
	if n != 1 {
		t.Fatalf("%d campagnes, 1 attendue", n)
	}
	// Preuve de propriété perdue : la programmation échoue proprement (refus journalisé).
	_, _ = e.db.Exec(context.Background(), `UPDATE assets SET proof_status = 'failed', proof_valid_until = NULL`)
	_, _ = e.db.Exec(context.Background(), `UPDATE schedules SET next_run_at = now() - interval '1 minute'`)
	e.srv.RunDueSchedules(context.Background(), time.Now())
	analyst.json("GET", "/api/schedules", nil, &list, 200)
	if !strings.Contains(list[0].LastError, "non prouvée") {
		t.Fatalf("erreur attendue : %+v", list[0])
	}
	// Auteur désactivé : la programmation est suspendue.
	_, _ = e.db.Exec(context.Background(), `UPDATE users SET disabled = true WHERE email = 'analyste@test'`)
	_, _ = e.db.Exec(context.Background(), `UPDATE schedules SET next_run_at = now() - interval '1 minute'`)
	e.srv.RunDueSchedules(context.Background(), time.Now())
	var enabled bool
	_ = e.db.QueryRow(context.Background(), `SELECT enabled FROM schedules`).Scan(&enabled)
	if enabled {
		t.Fatal("la programmation d'un auteur désactivé doit être suspendue")
	}
}
