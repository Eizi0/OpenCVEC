// Package httpapi expose l'API JSON d'OpenCVEC et sert l'application web.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Eizi0/OpenCVEC/internal/audit"
	"github.com/Eizi0/OpenCVEC/internal/auth"
	"github.com/Eizi0/OpenCVEC/internal/config"
	"github.com/Eizi0/OpenCVEC/internal/plugin"
	"github.com/Eizi0/OpenCVEC/internal/proof"
	"github.com/Eizi0/OpenCVEC/internal/receiver"
	"github.com/Eizi0/OpenCVEC/internal/runner"
	"github.com/Eizi0/OpenCVEC/internal/secrets"
)

const (
	sessionCookie = "opencvec_session"
	mfaCookie     = "opencvec_mfa"
	csrfHeader    = "X-OpenCVEC"
	sessionTTL    = 12 * time.Hour
)

// Rôles.
const (
	RoleAdmin   = "admin"
	RoleAnalyst = "analyst"
	RoleViewer  = "viewer"
)

var roleRank = map[string]int{RoleViewer: 1, RoleAnalyst: 2, RoleAdmin: 3}

// Server regroupe les dépendances des gestionnaires HTTP.
type Server struct {
	Cfg      config.Config
	DB       *pgxpool.Pool
	Web      fs.FS
	Log      *slog.Logger
	Secrets  *secrets.Box
	Audit    *audit.Log
	Runner   *runner.Runner
	Corr     *receiver.Correlator
	Verifier proof.Verifier
	Plugins  *plugin.Store
	// Version de l'application (affichée dans l'interface).
	Version string
	// DNSUp et HTTPUp indiquent si les listeners du récepteur ont démarré.
	DNSUp, HTTPUp bool

	limOnce sync.Once
	lim     *limits
}

func (s *Server) rl() *limits {
	s.limOnce.Do(func() {
		var db rlDB
		if s.DB != nil {
			db = s.DB
		}
		s.lim = newLimits(db)
	})
	return s.lim
}

// User est l'utilisateur authentifié.
type User struct {
	ID          int64  `json:"id"`
	Email       string `json:"email"`
	Name        string `json:"name"`
	Role        string `json:"role"`
	TOTPEnabled bool   `json:"totp_enabled"`
}

type ctxKey int

const ctxUser ctxKey = iota

type handler func(http.ResponseWriter, *http.Request, *User)

// Handler construit le routeur.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/login/totp", s.loginTOTP)
	mux.HandleFunc("POST /api/logout", s.logout)

	r := func(role, pattern string, fn handler) { mux.Handle(pattern, s.require(role, fn)) }
	// Tout utilisateur connecté.
	r(RoleViewer, "GET /api/me", s.me)
	r(RoleViewer, "POST /api/me/password", s.changePassword)
	r(RoleViewer, "POST /api/me/mfa/setup", s.mfaSetup)
	r(RoleViewer, "POST /api/me/mfa/enable", s.mfaEnable)
	r(RoleViewer, "POST /api/me/mfa/disable", s.mfaDisable)
	r(RoleViewer, "GET /api/dashboard", s.dashboard)
	r(RoleViewer, "GET /api/checkers", s.listCheckers)
	r(RoleViewer, "GET /api/assets", s.listAssets)
	r(RoleViewer, "GET /api/assets/{id}", s.getAsset)
	r(RoleViewer, "GET /api/campaigns", s.listCampaigns)
	r(RoleViewer, "GET /api/campaigns/{id}", s.getCampaign)
	r(RoleViewer, "GET /api/checks/{id}", s.getCheck)
	r(RoleViewer, "GET /api/callbacks", s.listCallbacks)
	r(RoleViewer, "GET /api/reports", s.listReports)
	r(RoleViewer, "GET /api/reports/{id}/download", s.downloadReport)
	r(RoleViewer, "GET /api/receiver", s.receiverStatus)
	r(RoleViewer, "GET /api/assets/{id}/canary", s.getFileCanary)

	// Analyste : assets, checks, rapports.
	r(RoleAnalyst, "POST /api/assets", s.createAsset)
	r(RoleAnalyst, "PUT /api/assets/{id}", s.updateAsset)
	r(RoleAnalyst, "POST /api/assets/{id}/verify", s.verifyAsset)
	r(RoleAnalyst, "POST /api/assets/{id}/token", s.renewAssetToken)
	r(RoleAnalyst, "DELETE /api/assets/{id}", s.deleteAsset)
	r(RoleAnalyst, "POST /api/campaigns", s.createCampaign)
	r(RoleAnalyst, "POST /api/campaigns/{id}/cancel", s.cancelCampaign)
	r(RoleAnalyst, "POST /api/reports", s.createReport)
	r(RoleAnalyst, "POST /api/assets/{id}/canary", s.setFileCanary)
	r(RoleAnalyst, "DELETE /api/assets/{id}/canary", s.deleteFileCanary)

	// Administrateur.
	r(RoleAdmin, "GET /api/users", s.listUsers)
	r(RoleAdmin, "POST /api/users", s.createUser)
	r(RoleAdmin, "PUT /api/users/{id}", s.updateUser)
	r(RoleAdmin, "POST /api/users/{id}/reset", s.resetUser)
	r(RoleAdmin, "GET /api/allowlist", s.listAllowlist)
	r(RoleAdmin, "POST /api/allowlist", s.addAllowlist)
	r(RoleAdmin, "POST /api/allowlist/{id}/renew", s.renewAllowlist)
	r(RoleAdmin, "DELETE /api/allowlist/{id}", s.deleteAllowlist)
	r(RoleAdmin, "GET /api/settings", s.getSettings)
	r(RoleAdmin, "PUT /api/settings", s.putSettings)
	r(RoleAdmin, "POST /api/receiver/selftest", s.selftest)
	r(RoleAdmin, "GET /api/plugins", s.listPlugins)
	r(RoleAdmin, "GET /api/plugins/registry", s.pluginRegistry)
	r(RoleAdmin, "POST /api/plugins/preview", s.previewPlugin)
	r(RoleAdmin, "POST /api/plugins", s.installPlugin)
	r(RoleAdmin, "PUT /api/plugins/{id}", s.togglePlugin)
	r(RoleAdmin, "DELETE /api/plugins/{id}", s.deletePlugin)
	r(RoleAdmin, "GET /api/publishers", s.listPublishers)
	r(RoleAdmin, "POST /api/publishers", s.addPublisher)
	r(RoleAdmin, "DELETE /api/publishers/{id}", s.deletePublisher)
	r(RoleAdmin, "GET /api/audit", s.listAudit)
	r(RoleAdmin, "GET /api/audit/verify", s.verifyAudit)
	r(RoleAdmin, "GET /api/audit/export.jsonl", s.exportAudit)

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { writeErr(w, http.StatusNotFound, "route inconnue") })
	mux.HandleFunc("/", s.serveWeb)
	return s.secure(mux)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if err := s.DB.Ping(r.Context()); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "base de données indisponible")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": s.Version})
}

// secure ajoute les en-têtes de sécurité et la protection CSRF : toute requête modifiante doit
// porter l'en-tête X-OpenCVEC, qu'un formulaire ou une image d'un site tiers ne peut pas ajouter.
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; frame-ancestors 'none'")
		if r.Method != http.MethodGet && r.Method != http.MethodHead && strings.HasPrefix(r.URL.Path, "/api/") {
			if r.Header.Get(csrfHeader) != "1" {
				writeErr(w, http.StatusForbidden, "en-tête X-OpenCVEC manquant")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// require vérifie la session et le rôle minimal.
func (s *Server) require(role string, fn handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || c.Value == "" {
			writeErr(w, http.StatusUnauthorized, "connexion requise")
			return
		}
		u := &User{}
		err = s.DB.QueryRow(r.Context(), `SELECT u.id, u.email, u.name, u.role, u.totp_enabled FROM sessions s
			JOIN users u ON u.id = s.user_id WHERE s.token_hash = $1 AND s.expires_at > now() AND NOT u.disabled`,
			auth.HashToken(c.Value)).Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.TOTPEnabled)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "session expirée, reconnectez-vous")
			return
		}
		// Double authentification imposée : seule son activation reste accessible.
		if s.Cfg.RequireMFA && !u.TOTPEnabled && !strings.HasPrefix(r.URL.Path, "/api/me") {
			writeErr(w, http.StatusForbidden, "activez la double authentification pour continuer")
			return
		}
		if roleRank[u.Role] < roleRank[role] {
			writeErr(w, http.StatusForbidden, "action réservée au rôle "+roleLabel(role))
			return
		}
		fn(w, r.WithContext(context.WithValue(r.Context(), ctxUser, u)), u)
	})
}

func roleLabel(r string) string {
	switch r {
	case RoleAdmin:
		return "administrateur"
	case RoleAnalyst:
		return "analyste"
	}
	return "lecteur"
}

// audit inscrit une action au journal ; une erreur d'écriture est journalisée sans bloquer la réponse.
func (s *Server) audit(r *http.Request, u *User, action, detail string) {
	var uid *int64
	actor := "système"
	if u != nil {
		uid = &u.ID
		actor = u.Email
	}
	if err := s.Audit.Write(context.Background(), uid, actor, action, detail, s.clientIP(r)); err != nil {
		s.Log.Error("écriture du journal d'audit", "err", err)
	}
}

func (s *Server) clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if s.Cfg.TrustProxy {
		if f := r.Header.Get("X-Forwarded-For"); f != "" {
			return strings.TrimSpace(strings.Split(f, ",")[0])
		}
	}
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}

func (s *Server) setCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: s.Cfg.SecureCookies,
		SameSite: http.SameSiteStrictMode, MaxAge: int(ttl.Seconds())})
}

func (s *Server) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", HttpOnly: true, Secure: s.Cfg.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

// serveWeb sert l'application monopage.
func (s *Server) serveWeb(w http.ResponseWriter, r *http.Request) {
	if s.Web == nil {
		http.Error(w, "Interface web non compilée (cd web && npm run build).", http.StatusNotFound)
		return
	}
	p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if p != "" && p != "index.html" {
		if f, err := s.Web.Open(p); err == nil {
			st, _ := f.Stat()
			f.Close()
			if st != nil && !st.IsDir() {
				if strings.HasPrefix(p, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				http.ServeFileFS(w, r, s.Web, p)
				return
			}
		}
	}
	b, err := fs.ReadFile(s.Web, "index.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, pgx.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "introuvable")
		return
	}
	s.Log.Error("erreur interne", "path", r.URL.Path, "err", err)
	writeErr(w, http.StatusInternalServerError, "erreur interne")
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "requête invalide : "+err.Error())
		return false
	}
	return true
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}
