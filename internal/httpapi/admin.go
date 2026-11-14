package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/Eizi0/OpenCVEC/internal/audit"
	"github.com/Eizi0/OpenCVEC/internal/auth"
	"github.com/Eizi0/OpenCVEC/internal/settings"
)

// ---------------------------------------------------------------------------------------------
// Utilisateurs

type userRow struct {
	ID          int64      `json:"id"`
	Email       string     `json:"email"`
	Name        string     `json:"name"`
	Role        string     `json:"role"`
	TOTPEnabled bool       `json:"totp_enabled"`
	Disabled    bool       `json:"disabled"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at"`
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request, u *User) {
	rows, err := s.DB.Query(r.Context(), `SELECT id, email, name, role, totp_enabled, disabled, created_at, last_login_at FROM users ORDER BY id`)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer rows.Close()
	out := []userRow{}
	for rows.Next() {
		var x userRow
		if err := rows.Scan(&x.ID, &x.Email, &x.Name, &x.Role, &x.TOTPEnabled, &x.Disabled, &x.CreatedAt, &x.LastLoginAt); err != nil {
			s.fail(w, r, err)
			return
		}
		out = append(out, x)
	}
	writeJSON(w, http.StatusOK, out)
}

func randomPassword() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func validRole(r string) bool { _, ok := roleRank[r]; return ok }

func (s *Server) createUser(w http.ResponseWriter, r *http.Request, u *User) {
	var in struct {
		Email    string `json:"email"`
		Name     string `json:"name"`
		Role     string `json:"role"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if !strings.Contains(email, "@") || len(email) > 200 {
		writeErr(w, http.StatusBadRequest, "adresse e-mail invalide")
		return
	}
	if !validRole(in.Role) {
		writeErr(w, http.StatusBadRequest, "rôle : admin, analyst ou viewer")
		return
	}
	pw := in.Password
	generated := pw == ""
	if generated {
		pw = randomPassword()
	} else if len(pw) < minPassword {
		writeErr(w, http.StatusBadRequest, "le mot de passe doit faire au moins 12 caractères")
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var id int64
	if err := s.DB.QueryRow(r.Context(), `INSERT INTO users (email, name, role, password_hash) VALUES ($1, $2, $3, $4)
		ON CONFLICT (email) DO NOTHING RETURNING id`, email, strings.TrimSpace(in.Name), in.Role, hash).Scan(&id); err != nil {
		writeErr(w, http.StatusConflict, "un compte existe déjà avec cette adresse")
		return
	}
	s.audit(r, u, "Utilisateur créé", fmt.Sprintf("%s · rôle %s", email, roleLabel(in.Role)))
	out := map[string]any{"id": id}
	if generated {
		out["password"] = pw
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) adminCount(ctx context.Context) int {
	var n int
	_ = s.DB.QueryRow(ctx, `SELECT count(*) FROM users WHERE role = 'admin' AND NOT disabled`).Scan(&n)
	return n
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request, u *User) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "identifiant invalide")
		return
	}
	var in struct {
		Name     string `json:"name"`
		Role     string `json:"role"`
		Disabled bool   `json:"disabled"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if !validRole(in.Role) {
		writeErr(w, http.StatusBadRequest, "rôle : admin, analyst ou viewer")
		return
	}
	var email, role string
	var disabled bool
	if err := s.DB.QueryRow(r.Context(), `SELECT email, role, disabled FROM users WHERE id = $1`, id).Scan(&email, &role, &disabled); err != nil {
		s.fail(w, r, err)
		return
	}
	if id == u.ID && (in.Role != RoleAdmin || in.Disabled) {
		writeErr(w, http.StatusBadRequest, "vous ne pouvez pas retirer vos propres droits d'administration")
		return
	}
	if role == RoleAdmin && !disabled && (in.Role != RoleAdmin || in.Disabled) && s.adminCount(r.Context()) <= 1 {
		writeErr(w, http.StatusBadRequest, "il doit rester au moins un administrateur actif")
		return
	}
	if _, err := s.DB.Exec(r.Context(), `UPDATE users SET name = $2, role = $3, disabled = $4 WHERE id = $1`, id, strings.TrimSpace(in.Name), in.Role, in.Disabled); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.Disabled {
		_, _ = s.DB.Exec(r.Context(), `DELETE FROM sessions WHERE user_id = $1`, id)
	}
	var changes []string
	if role != in.Role {
		changes = append(changes, roleLabel(role)+" → "+roleLabel(in.Role))
	}
	if disabled != in.Disabled {
		changes = append(changes, map[bool]string{true: "désactivé", false: "réactivé"}[in.Disabled])
	}
	if len(changes) > 0 {
		s.audit(r, u, "Rôle modifié", email+" : "+strings.Join(changes, ", "))
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) resetUser(w http.ResponseWriter, r *http.Request, u *User) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "identifiant invalide")
		return
	}
	pw := randomPassword()
	hash, err := auth.HashPassword(pw)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var email string
	if err := s.DB.QueryRow(r.Context(), `UPDATE users SET password_hash = $2, totp_enabled = false, totp_secret = ''
		WHERE id = $1 RETURNING email`, id, hash).Scan(&email); err != nil {
		s.fail(w, r, err)
		return
	}
	_, _ = s.DB.Exec(r.Context(), `DELETE FROM sessions WHERE user_id = $1`, id)
	s.audit(r, u, "Accès réinitialisé", email+" : nouveau mot de passe, double authentification à refaire")
	writeJSON(w, http.StatusOK, map[string]string{"password": pw})
}

// ---------------------------------------------------------------------------------------------
// Liste blanche

type allowRow struct {
	ID        int64     `json:"id"`
	CIDR      string    `json:"cidr"`
	Reason    string    `json:"reason"`
	AddedBy   string    `json:"added_by"`
	CreatedAt time.Time `json:"created_at"`
	ReviewAt  time.Time `json:"review_at"`
}

func (s *Server) listAllowlist(w http.ResponseWriter, r *http.Request, u *User) {
	rows, err := s.DB.Query(r.Context(), `SELECT l.id, l.cidr::text, l.reason, COALESCE(u.email, ''), l.created_at, l.review_at
		FROM allowlist l LEFT JOIN users u ON u.id = l.added_by ORDER BY l.cidr`)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer rows.Close()
	out := []allowRow{}
	for rows.Next() {
		var x allowRow
		if err := rows.Scan(&x.ID, &x.CIDR, &x.Reason, &x.AddedBy, &x.CreatedAt, &x.ReviewAt); err != nil {
			s.fail(w, r, err)
			return
		}
		out = append(out, x)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) addAllowlist(w http.ResponseWriter, r *http.Request, u *User) {
	var in struct {
		CIDR       string `json:"cidr"`
		Reason     string `json:"reason"`
		ReviewDays int    `json:"review_days"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(in.CIDR))
	if err != nil {
		if a, err2 := netip.ParseAddr(strings.TrimSpace(in.CIDR)); err2 == nil {
			p = netip.PrefixFrom(a, a.BitLen())
		} else {
			writeErr(w, http.StatusBadRequest, "plage CIDR invalide (ex. 10.20.0.0/24)")
			return
		}
	}
	p = p.Masked()
	if p.Addr().Is4() && p.Bits() < 8 || p.Addr().Is6() && p.Bits() < 32 {
		writeErr(w, http.StatusBadRequest, "plage trop large : /8 au maximum en IPv4, /32 en IPv6")
		return
	}
	reason := strings.TrimSpace(in.Reason)
	if len(reason) < 3 {
		writeErr(w, http.StatusBadRequest, "un motif est obligatoire")
		return
	}
	if in.ReviewDays <= 0 {
		in.ReviewDays = 30
	}
	if in.ReviewDays > 90 {
		writeErr(w, http.StatusBadRequest, "revue tous les 90 jours au maximum")
		return
	}
	review := time.Now().Add(time.Duration(in.ReviewDays) * 24 * time.Hour)
	if _, err := s.DB.Exec(r.Context(), `INSERT INTO allowlist (cidr, reason, added_by, review_at) VALUES ($1, $2, $3, $4)`, p.String(), reason, u.ID, review); err != nil {
		writeErr(w, http.StatusConflict, "cette plage est déjà autorisée")
		return
	}
	s.audit(r, u, "Liste blanche", fmt.Sprintf("ajout %s · motif : « %s » · revue %d j", p, reason, in.ReviewDays))
	writeJSON(w, http.StatusCreated, map[string]bool{"ok": true})
}

func (s *Server) renewAllowlist(w http.ResponseWriter, r *http.Request, u *User) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "identifiant invalide")
		return
	}
	var cidr string
	if err := s.DB.QueryRow(r.Context(), `UPDATE allowlist SET review_at = now() + interval '30 days' WHERE id = $1 RETURNING cidr::text`, id).Scan(&cidr); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, u, "Liste blanche", "revue de "+cidr+" : prolongée de 30 jours")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) deleteAllowlist(w http.ResponseWriter, r *http.Request, u *User) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "identifiant invalide")
		return
	}
	var cidr string
	if err := s.DB.QueryRow(r.Context(), `DELETE FROM allowlist WHERE id = $1 RETURNING cidr::text`, id).Scan(&cidr); err != nil {
		s.fail(w, r, err)
		return
	}
	// Les assets prouvés par liste blanche sont revérifiés : ceux que la plage couvrait perdent leur preuve.
	rows, err := s.DB.Query(r.Context(), `SELECT `+assetCols+` FROM assets a WHERE a.proof_method = 'allowlist' AND a.proof_status = 'valid'`)
	if err == nil {
		var list []Asset
		for rows.Next() {
			if a, err := scanAsset(rows); err == nil {
				list = append(list, a)
			}
		}
		rows.Close()
		for _, a := range list {
			_, _ = s.revalidate(r.Context(), a)
		}
	}
	s.audit(r, u, "Liste blanche", "retrait de "+cidr)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------------------------------------
// Réglages et récepteur

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request, u *User) {
	g, err := settings.Load(r.Context(), s.DB)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request, u *User) {
	var g settings.General
	if !readJSON(w, r, &g) {
		return
	}
	before, _ := settings.Load(r.Context(), s.DB)
	if err := settings.Save(r.Context(), s.DB, g); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if before.AllowUnsignedPlugins != g.AllowUnsignedPlugins {
		s.audit(r, u, "Mode développeur", map[bool]string{true: "activé : plugins non signés autorisés", false: "désactivé : seuls les plugins signés sont chargés"}[g.AllowUnsignedPlugins])
		if s.Plugins != nil {
			_ = s.Plugins.Load(r.Context(), g.AllowUnsignedPlugins)
		}
	}
	b, _ := json.Marshal(g)
	s.audit(r, u, "Réglages modifiés", string(b))
	writeJSON(w, http.StatusOK, g)
}

func (s *Server) receiverStatus(w http.ResponseWriter, r *http.Request, u *User) {
	ns := s.Cfg.NSName
	writeJSON(w, http.StatusOK, map[string]any{
		"zone": s.Cfg.CanaryZone, "ns_name": ns, "ip": s.Cfg.CanaryIP,
		"dns_addr": s.Cfg.DNSAddr, "http_addr": s.Cfg.CanaryHTTPAddr,
		"dns_up": s.DNSUp, "http_up": s.HTTPUp, "resolvers": s.Cfg.ProofResolvers,
		"records": []string{
			fmt.Sprintf("%s.\tNS\t%s.", s.Cfg.CanaryZone, ns),
			fmt.Sprintf("%s.\tA\t%s", ns, s.Cfg.CanaryIP),
		},
	})
}

type selftestStep struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

func selftestLabel() string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	return "selftest-" + hex.EncodeToString(b)
}

func localAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// selftest vérifie le récepteur : écoute locale DNS, délégation publique et écoute HTTP.
func (s *Server) selftest(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	var steps []selftestStep
	wait := func(label string, send func() error) (bool, string) {
		ch, done := s.Corr.ExpectSelftest(label)
		defer done()
		if err := send(); err != nil {
			return false, err.Error()
		}
		select {
		case ev := <-ch:
			return true, fmt.Sprintf("requête %s %s reçue depuis %s", ev.Proto, ev.QType, ev.Source)
		case <-time.After(5 * time.Second):
			return false, "aucune requête reçue en 5 s"
		}
	}
	query := func(server, name string) error {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), dns.TypeA)
		m.RecursionDesired = true
		_, _, err := (&dns.Client{Timeout: 4 * time.Second}).ExchangeContext(ctx, m, server)
		return err
	}
	if !s.DNSUp {
		steps = append(steps, selftestStep{Name: "DNS autoritaire local", Detail: "listener DNS désactivé ou non démarré (" + s.Cfg.DNSAddr + ")"})
	} else {
		l := selftestLabel()
		ok, d := wait(l, func() error { return query(localAddr(s.Cfg.DNSAddr), l+"."+s.Cfg.CanaryZone) })
		steps = append(steps, selftestStep{Name: "DNS autoritaire local (" + s.Cfg.DNSAddr + ")", OK: ok, Detail: d})
		for _, res := range s.Cfg.ProofResolvers {
			l := selftestLabel()
			ok, d := wait(l, func() error { return query(res, l+"."+s.Cfg.CanaryZone) })
			if !ok {
				d += " : vérifiez la délégation NS de la zone et l'ouverture du port 53 (UDP et TCP)"
			}
			steps = append(steps, selftestStep{Name: "Délégation publique via " + res, OK: ok, Detail: d})
		}
	}
	if !s.HTTPUp {
		steps = append(steps, selftestStep{Name: "Récepteur HTTP", Detail: "listener HTTP désactivé ou non démarré (" + s.Cfg.CanaryHTTPAddr + ")"})
	} else {
		l := selftestLabel()
		ok, d := wait(l, func() error {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+localAddr(s.Cfg.CanaryHTTPAddr)+"/", nil)
			req.Host = l + "." + s.Cfg.CanaryZone
			resp, err := (&http.Client{Timeout: 4 * time.Second}).Do(req)
			if err == nil {
				resp.Body.Close()
			}
			return err
		})
		steps = append(steps, selftestStep{Name: "Récepteur HTTP local (" + s.Cfg.CanaryHTTPAddr + ")", OK: ok, Detail: d})
	}
	okAll := true
	for _, st := range steps {
		okAll = okAll && st.OK
	}
	s.audit(r, u, "Auto-test du récepteur", map[bool]string{true: "réussi", false: "échecs constatés"}[okAll])
	writeJSON(w, http.StatusOK, map[string]any{"ok": okAll, "steps": steps})
}

// ---------------------------------------------------------------------------------------------
// Journal d'audit

func (s *Server) auditQuery(r *http.Request) (string, []any) {
	q := r.URL.Query()
	where := `WHERE true`
	var args []any
	if v := q.Get("user"); v != "" {
		args = append(args, v)
		where += ` AND actor = $` + strconv.Itoa(len(args))
	}
	if v := q.Get("action"); v != "" {
		args = append(args, v)
		where += ` AND action = $` + strconv.Itoa(len(args))
	}
	if d, err := strconv.Atoi(q.Get("days")); err == nil && d > 0 {
		args = append(args, time.Now().Add(-time.Duration(d)*24*time.Hour))
		where += ` AND at > $` + strconv.Itoa(len(args))
	}
	return where, args
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request, u *User) {
	where, args := s.auditQuery(r)
	rows, err := s.DB.Query(r.Context(), `SELECT id, at, user_id, actor, action, detail, ip, hash FROM audit_log `+where+` ORDER BY id DESC LIMIT 500`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer rows.Close()
	out := []audit.Entry{}
	for rows.Next() {
		var e audit.Entry
		var h []byte
		if err := rows.Scan(&e.ID, &e.At, &e.UserID, &e.Actor, &e.Action, &e.Detail, &e.IP, &h); err != nil {
			s.fail(w, r, err)
			return
		}
		e.Hash = audit.Hex(h)
		out = append(out, e)
	}
	var actors, actions []string
	_ = scanStrings(r.Context(), s, `SELECT DISTINCT actor FROM audit_log ORDER BY 1`, &actors)
	_ = scanStrings(r.Context(), s, `SELECT DISTINCT action FROM audit_log ORDER BY 1`, &actions)
	writeJSON(w, http.StatusOK, map[string]any{"entries": out, "actors": actors, "actions": actions})
}

func scanStrings(ctx context.Context, s *Server, q string, out *[]string) error {
	rows, err := s.DB.Query(ctx, q)
	if err != nil {
		return err
	}
	defer rows.Close()
	*out = []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err == nil {
			*out = append(*out, v)
		}
	}
	return rows.Err()
}

func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request, u *User) {
	res, err := s.Audit.Verify(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) exportAudit(w http.ResponseWriter, r *http.Request, u *User) {
	where, args := s.auditQuery(r)
	rows, err := s.DB.Query(r.Context(), `SELECT id, at, user_id, actor, action, detail, ip, hash FROM audit_log `+where+` ORDER BY id`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer rows.Close()
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="opencvec-audit.jsonl"`)
	enc := json.NewEncoder(w)
	for rows.Next() {
		var e audit.Entry
		var h []byte
		if err := rows.Scan(&e.ID, &e.At, &e.UserID, &e.Actor, &e.Action, &e.Detail, &e.IP, &h); err != nil {
			return
		}
		e.Hash = audit.Hex(h)
		_ = enc.Encode(e)
	}
	s.audit(r, u, "Journal exporté", "export JSONL")
}
