package httpapi

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"time"

	"rsc.io/qr"

	"github.com/Eizi0/OpenCVEC/internal/auth"
)

const (
	mfaChallengeTTL = 5 * time.Minute
	mfaMaxAttempts  = 5
	minPassword     = 12
)

var (
	dummyOnce sync.Once
	dummy     string
)

// dummyHash sert à comparer un mot de passe même quand le compte n'existe pas.
func dummyHash() string {
	dummyOnce.Do(func() { dummy, _ = auth.HashPassword(auth.NewToken()) })
	return dummy
}

func (s *Server) startSession(ctx context.Context, w http.ResponseWriter, userID int64) error {
	tok := auth.NewToken()
	if _, err := s.DB.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now()`); err != nil {
		return err
	}
	if _, err := s.DB.Exec(ctx, `INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)`,
		auth.HashToken(tok), userID, time.Now().Add(sessionTTL)); err != nil {
		return err
	}
	s.setCookie(w, sessionCookie, tok, sessionTTL)
	_, err := s.DB.Exec(ctx, `UPDATE users SET last_login_at = now() WHERE id = $1`, userID)
	return err
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	ip := s.clientIP(r)
	now := time.Now()
	if ok, wait := s.rl().loginIP.allow(ip, now); !ok {
		tooMany(w, wait)
		return
	}
	if ok, wait := s.rl().loginEmail.allow(email, now); !ok {
		tooMany(w, wait)
		return
	}
	var id int64
	var hash string
	var totp, disabled bool
	err := s.DB.QueryRow(r.Context(), `SELECT id, password_hash, totp_enabled, disabled FROM users WHERE email = $1`, email).
		Scan(&id, &hash, &totp, &disabled)
	if err != nil || disabled || !auth.CheckPassword(hash, in.Password) {
		if err != nil {
			// Temps de réponse comparable que le compte existe ou non.
			auth.CheckPassword(dummyHash(), in.Password)
		}
		s.audit(r, nil, "Connexion refusée", "identifiants invalides pour "+email)
		writeErr(w, http.StatusUnauthorized, "adresse e-mail ou mot de passe incorrect")
		return
	}
	s.rl().loginEmail.reset(email)
	if totp {
		tok := auth.NewToken()
		if _, err := s.DB.Exec(r.Context(), `INSERT INTO mfa_challenges (token_hash, user_id, expires_at) VALUES ($1, $2, $3)`,
			auth.HashToken(tok), id, time.Now().Add(mfaChallengeTTL)); err != nil {
			s.fail(w, r, err)
			return
		}
		s.setCookie(w, mfaCookie, tok, mfaChallengeTTL)
		writeJSON(w, http.StatusOK, map[string]bool{"mfa_required": true})
		return
	}
	if err := s.startSession(r.Context(), w, id); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, &User{ID: id, Email: email}, "Connexion", "mot de passe")
	writeJSON(w, http.StatusOK, map[string]bool{"mfa_required": false})
}

func (s *Server) loginTOTP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if ok, wait := s.rl().totpIP.allow(s.clientIP(r), time.Now()); !ok {
		tooMany(w, wait)
		return
	}
	c, err := r.Cookie(mfaCookie)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "session de connexion expirée, recommencez")
		return
	}
	ctx := r.Context()
	var uid int64
	var attempts int
	// Tentative comptée avant la vérification : pas de forçage possible.
	err = s.DB.QueryRow(ctx, `UPDATE mfa_challenges SET attempts = attempts + 1
		WHERE token_hash = $1 AND expires_at > now() RETURNING user_id, attempts`, auth.HashToken(c.Value)).Scan(&uid, &attempts)
	if err != nil || attempts > mfaMaxAttempts {
		_, _ = s.DB.Exec(ctx, `DELETE FROM mfa_challenges WHERE token_hash = $1`, auth.HashToken(c.Value))
		s.clearCookie(w, mfaCookie)
		writeErr(w, http.StatusUnauthorized, "session de connexion expirée ou trop de tentatives, recommencez")
		return
	}
	var email, secret string
	var last int64
	if err := s.DB.QueryRow(ctx, `SELECT email, totp_secret, totp_last_counter FROM users WHERE id = $1`, uid).Scan(&email, &secret, &last); err != nil {
		s.fail(w, r, err)
		return
	}
	plain, err := s.Secrets.Open(secret)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	counter, ok := auth.VerifyTOTP(plain, in.Code, time.Now(), last)
	if !ok {
		s.audit(r, &User{ID: uid, Email: email}, "Connexion refusée", "code TOTP invalide")
		writeErr(w, http.StatusUnauthorized, "code incorrect")
		return
	}
	if _, err := s.DB.Exec(ctx, `UPDATE users SET totp_last_counter = $2 WHERE id = $1`, uid, counter); err != nil {
		s.fail(w, r, err)
		return
	}
	_, _ = s.DB.Exec(ctx, `DELETE FROM mfa_challenges WHERE token_hash = $1`, auth.HashToken(c.Value))
	s.clearCookie(w, mfaCookie)
	if err := s.startSession(ctx, w, uid); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, &User{ID: uid, Email: email}, "Connexion", "mot de passe + TOTP")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_, _ = s.DB.Exec(r.Context(), `DELETE FROM sessions WHERE token_hash = $1`, auth.HashToken(c.Value))
	}
	s.clearCookie(w, sessionCookie)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request, u *User) {
	writeJSON(w, http.StatusOK, map[string]any{"user": u, "require_mfa": s.Cfg.RequireMFA, "canary_zone": s.Cfg.CanaryZone, "version": s.Version})
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, u *User) {
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	var hash string
	if err := s.DB.QueryRow(r.Context(), `SELECT password_hash FROM users WHERE id = $1`, u.ID).Scan(&hash); err != nil {
		s.fail(w, r, err)
		return
	}
	if !auth.CheckPassword(hash, in.Current) {
		writeErr(w, http.StatusBadRequest, "mot de passe actuel incorrect")
		return
	}
	if len(in.New) < minPassword {
		writeErr(w, http.StatusBadRequest, "le nouveau mot de passe doit faire au moins 12 caractères")
		return
	}
	nh, err := auth.HashPassword(in.New)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.DB.Exec(r.Context(), `UPDATE users SET password_hash = $2 WHERE id = $1`, u.ID, nh); err != nil {
		s.fail(w, r, err)
		return
	}
	// Les autres sessions sont fermées.
	c, _ := r.Cookie(sessionCookie)
	_, _ = s.DB.Exec(r.Context(), `DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2`, u.ID, auth.HashToken(c.Value))
	s.audit(r, u, "Mot de passe modifié", "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) mfaSetup(w http.ResponseWriter, r *http.Request, u *User) {
	if u.TOTPEnabled {
		writeErr(w, http.StatusConflict, "la double authentification est déjà active")
		return
	}
	secret := auth.NewTOTPSecret()
	sealed, err := s.Secrets.Seal(secret)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.DB.Exec(r.Context(), `UPDATE users SET totp_secret = $2 WHERE id = $1`, u.ID, sealed); err != nil {
		s.fail(w, r, err)
		return
	}
	uri := auth.TOTPURI("OpenCVEC", u.Email, secret)
	out := map[string]string{"secret": secret, "uri": uri}
	if code, err := qr.Encode(uri, qr.M); err == nil {
		out["qr"] = "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) mfaEnable(w http.ResponseWriter, r *http.Request, u *User) {
	var in struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	var secret string
	var last int64
	if err := s.DB.QueryRow(r.Context(), `SELECT totp_secret, totp_last_counter FROM users WHERE id = $1`, u.ID).Scan(&secret, &last); err != nil {
		s.fail(w, r, err)
		return
	}
	plain, err := s.Secrets.Open(secret)
	if err != nil || plain == "" {
		writeErr(w, http.StatusBadRequest, "commencez par générer un secret")
		return
	}
	counter, ok := auth.VerifyTOTP(plain, in.Code, time.Now(), last)
	if !ok {
		writeErr(w, http.StatusBadRequest, "code incorrect")
		return
	}
	if _, err := s.DB.Exec(r.Context(), `UPDATE users SET totp_enabled = true, totp_last_counter = $2 WHERE id = $1`, u.ID, counter); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, u, "Double authentification activée", "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) mfaDisable(w http.ResponseWriter, r *http.Request, u *User) {
	if s.Cfg.RequireMFA {
		writeErr(w, http.StatusForbidden, "la double authentification est imposée sur cette instance")
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	var hash string
	if err := s.DB.QueryRow(r.Context(), `SELECT password_hash FROM users WHERE id = $1`, u.ID).Scan(&hash); err != nil {
		s.fail(w, r, err)
		return
	}
	if !auth.CheckPassword(hash, in.Password) {
		writeErr(w, http.StatusBadRequest, "mot de passe incorrect")
		return
	}
	if _, err := s.DB.Exec(r.Context(), `UPDATE users SET totp_enabled = false, totp_secret = '' WHERE id = $1`, u.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, u, "Double authentification désactivée", "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
