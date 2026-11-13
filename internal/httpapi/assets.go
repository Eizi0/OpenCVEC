package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/Eizi0/OpenCVEC/internal/proof"
	"github.com/Eizi0/OpenCVEC/internal/settings"
)

// Asset est la représentation JSON d'un asset.
type Asset struct {
	ID              int64      `json:"id"`
	Host            string     `json:"host"`
	Kind            string     `json:"kind"`
	Tags            []string   `json:"tags"`
	Scheme          string     `json:"scheme"`
	Port            int        `json:"port"`
	ProofMethod     string     `json:"proof_method"`
	ProofToken      string     `json:"proof_token"`
	ProofTokenUntil time.Time  `json:"proof_token_expires"`
	ProofStatus     string     `json:"proof_status"`
	ProofDetail     string     `json:"proof_detail"`
	ProofCheckedAt  *time.Time `json:"proof_checked_at"`
	ProofValidUntil *time.Time `json:"proof_valid_until"`
	ResolvedIPs     []string   `json:"resolved_ips"`
	CreatedAt       time.Time  `json:"created_at"`
	// Owned : preuve valide et non expirée (seul cas où un check est permis).
	Owned       bool   `json:"owned"`
	LastVerdict string `json:"last_verdict"`
	LastChecker string `json:"last_checker"`
	// Instructions de preuve.
	TXTName      string `json:"txt_name,omitempty"`
	TXTValue     string `json:"txt_value,omitempty"`
	WellKnownURL string `json:"well_known_url,omitempty"`
	DefaultURL   string `json:"default_url"`
}

const assetCols = `a.id, a.host, a.kind, a.tags, a.scheme, a.port, a.proof_method, a.proof_token, a.proof_token_expires,
	a.proof_status, a.proof_detail, a.proof_checked_at, a.proof_valid_until, a.resolved_ips, a.created_at,
	COALESCE((SELECT k.verdict FROM checks k WHERE k.asset_id = a.id AND k.verdict IS NOT NULL ORDER BY k.id DESC LIMIT 1), ''),
	COALESCE((SELECT k.checker FROM checks k WHERE k.asset_id = a.id AND k.verdict IS NOT NULL ORDER BY k.id DESC LIMIT 1), '')`

type scanner interface{ Scan(...any) error }

func scanAsset(row scanner) (Asset, error) {
	var a Asset
	err := row.Scan(&a.ID, &a.Host, &a.Kind, &a.Tags, &a.Scheme, &a.Port, &a.ProofMethod, &a.ProofToken, &a.ProofTokenUntil,
		&a.ProofStatus, &a.ProofDetail, &a.ProofCheckedAt, &a.ProofValidUntil, &a.ResolvedIPs, &a.CreatedAt, &a.LastVerdict, &a.LastChecker)
	if err != nil {
		return a, err
	}
	a.Owned = a.ProofStatus == "valid" && a.ProofValidUntil != nil && a.ProofValidUntil.After(time.Now())
	switch a.ProofMethod {
	case "dns_txt":
		a.TXTName = proof.TXTName(a.Host)
		a.TXTValue = proof.TXTKey + a.ProofToken
	case "well_known":
		a.WellKnownURL = a.Scheme + "://" + hostPort(a.Host, a.Port) + proof.WellKnownPath(a.ID)
	}
	if a.Kind != "cidr" {
		a.DefaultURL = a.Scheme + "://" + hostPort(a.Host, a.Port) + "/"
	}
	return a, nil
}

func hostPort(h string, port int) string {
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	if port > 0 {
		return fmt.Sprintf("%s:%d", h, port)
	}
	return h
}

func (s *Server) listAssets(w http.ResponseWriter, r *http.Request, u *User) {
	rows, err := s.DB.Query(r.Context(), `SELECT `+assetCols+` FROM assets a ORDER BY a.host`)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer rows.Close()
	out := []Asset{}
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		out = append(out, a)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) loadAsset(ctx context.Context, id int64) (Asset, error) {
	return scanAsset(s.DB.QueryRow(ctx, `SELECT `+assetCols+` FROM assets a WHERE a.id = $1`, id))
}

func (s *Server) getAsset(w http.ResponseWriter, r *http.Request, u *User) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "identifiant invalide")
		return
	}
	a, err := s.loadAsset(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

var domainRe = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// classifyHost valide et normalise l'hôte déclaré.
func classifyHost(h string) (string, string, error) {
	h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
	if h == "" {
		return "", "", fmt.Errorf("indiquez un nom d'hôte, une IP ou une plage CIDR")
	}
	if p, err := netip.ParsePrefix(h); err == nil {
		if p.Addr().Is4() && p.Bits() < 16 || p.Addr().Is6() && p.Bits() < 48 {
			return "", "", fmt.Errorf("plage trop large : /16 au maximum en IPv4, /48 en IPv6")
		}
		return p.Masked().String(), "cidr", nil
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Unmap().String(), "ip", nil
	}
	if len(h) > 253 || !domainRe.MatchString(h) {
		return "", "", fmt.Errorf("nom d'hôte invalide")
	}
	return h, "domain", nil
}

type assetInput struct {
	Host        string   `json:"host"`
	Tags        []string `json:"tags"`
	ProofMethod string   `json:"proof_method"`
	Scheme      string   `json:"scheme"`
	Port        int      `json:"port"`
}

func cleanTags(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		if t != "" && len(t) <= 40 && !seen[t] && len(out) < 20 {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

func validateAssetInput(in *assetInput, kind string) error {
	if in.Scheme == "" {
		in.Scheme = "https"
	}
	if in.Scheme != "http" && in.Scheme != "https" {
		return fmt.Errorf("schéma : http ou https")
	}
	if in.Port < 0 || in.Port > 65535 {
		return fmt.Errorf("port invalide")
	}
	switch in.ProofMethod {
	case "dns_txt":
		if kind != "domain" {
			return fmt.Errorf("la preuve DNS TXT ne s'applique qu'à un nom de domaine")
		}
	case "well_known":
		if kind == "cidr" {
			return fmt.Errorf("une plage CIDR se prouve uniquement par la liste blanche")
		}
	case "allowlist":
	default:
		return fmt.Errorf("méthode de preuve : dns_txt, well_known ou allowlist")
	}
	return nil
}

func (s *Server) createAsset(w http.ResponseWriter, r *http.Request, u *User) {
	var in assetInput
	if !readJSON(w, r, &in) {
		return
	}
	host, kind, err := classifyHost(in.Host)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateAssetInput(&in, kind); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var id int64
	err = s.DB.QueryRow(r.Context(), `INSERT INTO assets (host, kind, tags, scheme, port, proof_method, proof_token, proof_token_expires, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (host) DO NOTHING RETURNING id`,
		host, kind, cleanTags(in.Tags), in.Scheme, in.Port, in.ProofMethod, proof.NewToken(), time.Now().Add(proof.TokenTTL), u.ID).Scan(&id)
	if err != nil {
		writeErr(w, http.StatusConflict, "cet asset existe déjà")
		return
	}
	s.audit(r, u, "Asset déclaré", fmt.Sprintf("%s · méthode %s", host, in.ProofMethod))
	a, err := s.loadAsset(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, a)
}

func (s *Server) updateAsset(w http.ResponseWriter, r *http.Request, u *User) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "identifiant invalide")
		return
	}
	var in assetInput
	if !readJSON(w, r, &in) {
		return
	}
	a, err := s.loadAsset(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if in.ProofMethod == "" {
		in.ProofMethod = a.ProofMethod
	}
	if err := validateAssetInput(&in, a.Kind); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Changer de méthode, de schéma ou de port invalide la preuve : elle doit être refaite.
	reset := in.ProofMethod != a.ProofMethod || in.Scheme != a.Scheme || in.Port != a.Port
	q := `UPDATE assets SET tags = $2, scheme = $3, port = $4, proof_method = $5`
	if reset {
		q += `, proof_status = 'pending', proof_valid_until = NULL, proof_detail = 'preuve à refaire après modification'`
	}
	if _, err := s.DB.Exec(r.Context(), q+` WHERE id = $1`, id, cleanTags(in.Tags), in.Scheme, in.Port, in.ProofMethod); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, u, "Asset modifié", a.Host)
	a, _ = s.loadAsset(r.Context(), id)
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) renewAssetToken(w http.ResponseWriter, r *http.Request, u *User) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "identifiant invalide")
		return
	}
	if _, err := s.DB.Exec(r.Context(), `UPDATE assets SET proof_token = $2, proof_token_expires = $3, proof_status = 'pending',
		proof_valid_until = NULL, proof_detail = 'nouveau jeton à publier' WHERE id = $1`, id, proof.NewToken(), time.Now().Add(proof.TokenTTL)); err != nil {
		s.fail(w, r, err)
		return
	}
	a, err := s.loadAsset(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, u, "Jeton de preuve régénéré", a.Host)
	writeJSON(w, http.StatusOK, a)
}

// revalidate vérifie (à nouveau) la preuve de propriété d'un asset et enregistre le résultat.
// Une preuve déjà validée reste vérifiable avec son jeton même après l'expiration de ce dernier :
// le délai de 72 h ne concerne que la première publication.
func (s *Server) revalidate(ctx context.Context, a Asset) (proof.Result, error) {
	if a.ProofStatus != "valid" && a.ProofTokenUntil.Before(time.Now()) {
		res := proof.Result{Detail: "jeton de preuve expiré : régénérez-le puis publiez la nouvelle valeur"}
		_, err := s.DB.Exec(ctx, `UPDATE assets SET proof_status = 'failed', proof_detail = $2, proof_checked_at = now() WHERE id = $1`, a.ID, res.Detail)
		return res, err
	}
	allow, err := settings.Allowlist(ctx, s.DB)
	if err != nil {
		return proof.Result{}, err
	}
	res := s.Verifier.Verify(ctx, proof.Asset{ID: a.ID, Host: a.Host, Kind: a.Kind, Scheme: a.Scheme, Port: a.Port, Method: a.ProofMethod, Token: a.ProofToken}, allow)
	if res.OK {
		until := time.Now().Add(proof.ProofTTL)
		if a.ProofMethod == "allowlist" {
			// Une preuve par liste blanche ne dure pas plus longtemps que l'autorisation elle-même.
			var review time.Time
			if err := s.DB.QueryRow(ctx, `SELECT COALESCE(min(review_at), now()) FROM allowlist WHERE review_at > now() AND cidr >>= $1::inet`,
				firstIP(a, res)).Scan(&review); err == nil && review.Before(until) {
				until = review
			}
		}
		ips := res.ResolvedIPs
		if ips == nil {
			ips = []string{}
		}
		_, err = s.DB.Exec(ctx, `UPDATE assets SET proof_status = 'valid', proof_detail = $2, proof_checked_at = now(),
			proof_valid_until = $3, resolved_ips = $4 WHERE id = $1`, a.ID, res.Detail, until, ips)
	} else {
		_, err = s.DB.Exec(ctx, `UPDATE assets SET proof_status = 'failed', proof_detail = $2, proof_checked_at = now(),
			proof_valid_until = NULL WHERE id = $1`, a.ID, res.Detail)
	}
	return res, err
}

func firstIP(a Asset, res proof.Result) string {
	if p, err := netip.ParsePrefix(a.Host); err == nil {
		return p.Addr().String()
	}
	if len(res.ResolvedIPs) > 0 {
		return res.ResolvedIPs[0]
	}
	return a.Host
}

func (s *Server) verifyAsset(w http.ResponseWriter, r *http.Request, u *User) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "identifiant invalide")
		return
	}
	a, err := s.loadAsset(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	res, err := s.revalidate(r.Context(), a)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	verdict := "réussie"
	if !res.OK {
		verdict = "échouée"
	}
	s.audit(r, u, "Preuve de propriété", fmt.Sprintf("%s · %s · %s : %s", a.Host, a.ProofMethod, verdict, res.Detail))
	a, _ = s.loadAsset(r.Context(), id)
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) deleteAsset(w http.ResponseWriter, r *http.Request, u *User) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "identifiant invalide")
		return
	}
	var host string
	if err := s.DB.QueryRow(r.Context(), `DELETE FROM assets WHERE id = $1 RETURNING host`, id).Scan(&host); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, u, "Asset supprimé", host)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
