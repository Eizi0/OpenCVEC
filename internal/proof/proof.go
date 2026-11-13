// Package proof vérifie qu'une organisation possède bien un asset avant tout check.
//
// Trois méthodes :
//   - dns_txt : enregistrement TXT « opencvec-verif=<jeton> » sur _opencvec.<hôte>, lu via plusieurs
//     résolveurs ; la majorité de ceux qui répondent doit le voir ;
//   - well_known : fichier /.well-known/opencvec-<id>.txt contenant le jeton, servi par l'hôte ;
//   - allowlist : toutes les adresses de l'asset appartiennent à une plage autorisée par un administrateur.
package proof

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/Eizi0/OpenCVEC/internal/netguard"
)

// Durées de validité.
const (
	TokenTTL = 72 * time.Hour
	ProofTTL = 30 * 24 * time.Hour
	TXTLabel = "_opencvec"
	TXTKey   = "opencvec-verif="
)

// NewToken renvoie un jeton de preuve lisible (XXXX-XXXX-XXXX-XXXX, alphabet sans ambiguïté).
func NewToken() string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	var sb strings.Builder
	for i, c := range b {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(alphabet[int(c)%len(alphabet)])
	}
	return sb.String()
}

// Asset est la vue de l'asset nécessaire à la vérification.
type Asset struct {
	ID     int64
	Host   string
	Kind   string // domain, ip, cidr
	Scheme string
	Port   int
	Method string // dns_txt, well_known, allowlist
	Token  string
}

// Result est le résultat d'une vérification.
type Result struct {
	OK          bool
	Detail      string
	ResolvedIPs []string
}

// Verifier vérifie les preuves.
type Verifier struct {
	Resolvers []string
	Timeout   time.Duration
}

// WellKnownPath renvoie le chemin du fichier de preuve.
func WellKnownPath(id int64) string { return fmt.Sprintf("/.well-known/opencvec-%d.txt", id) }

// TXTName renvoie le nom DNS de l'enregistrement de preuve.
func TXTName(host string) string { return TXTLabel + "." + strings.TrimSuffix(host, ".") }

// Prefix renvoie la plage d'un asset IP ou CIDR.
func Prefix(a Asset) (netip.Prefix, bool) {
	if a.Kind == "cidr" {
		p, err := netip.ParsePrefix(a.Host)
		return p.Masked(), err == nil
	}
	if a.Kind == "ip" {
		ip, err := netip.ParseAddr(a.Host)
		if err != nil {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(ip, ip.BitLen()), true
	}
	return netip.Prefix{}, false
}

// Verify vérifie la preuve de propriété d'un asset.
func (v Verifier) Verify(ctx context.Context, a Asset, allow []netip.Prefix) Result {
	if v.Timeout == 0 {
		v.Timeout = 5 * time.Second
	}
	switch a.Method {
	case "allowlist":
		return v.allowlist(ctx, a, allow)
	case "dns_txt":
		if a.Kind != "domain" {
			return Result{Detail: "la preuve DNS TXT ne s'applique qu'à un nom de domaine"}
		}
		r := v.txt(ctx, a)
		if r.OK {
			r.ResolvedIPs = resolve(ctx, a.Host)
		}
		return r
	case "well_known":
		return v.wellKnown(ctx, a, allow)
	}
	return Result{Detail: "méthode de preuve inconnue"}
}

func resolve(ctx context.Context, host string) []string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.Unmap().String())
	}
	return out
}

func (v Verifier) allowlist(ctx context.Context, a Asset, allow []netip.Prefix) Result {
	contained := func(p netip.Prefix) bool {
		for _, al := range allow {
			if al.Bits() <= p.Bits() && al.Contains(p.Addr()) {
				return true
			}
		}
		return false
	}
	if p, ok := Prefix(a); ok {
		if contained(p) {
			return Result{OK: true, Detail: fmt.Sprintf("%s est incluse dans la liste blanche", p), ResolvedIPs: []string{p.Addr().String()}}
		}
		return Result{Detail: fmt.Sprintf("%s n'est pas entièrement couverte par la liste blanche", p)}
	}
	ips := resolve(ctx, a.Host)
	if len(ips) == 0 {
		return Result{Detail: "le nom ne se résout pas"}
	}
	for _, s := range ips {
		ip, _ := netip.ParseAddr(s)
		if !contained(netip.PrefixFrom(ip, ip.BitLen())) {
			return Result{Detail: fmt.Sprintf("%s se résout en %s, hors liste blanche", a.Host, s), ResolvedIPs: ips}
		}
	}
	return Result{OK: true, Detail: fmt.Sprintf("%s se résout uniquement dans la liste blanche (%s)", a.Host, strings.Join(ips, ", ")), ResolvedIPs: ips}
}

func (v Verifier) txt(ctx context.Context, a Asset) Result {
	name := dns.Fqdn(TXTName(a.Host))
	want := TXTKey + a.Token
	c := &dns.Client{Timeout: v.Timeout}
	var responded, found int
	for _, res := range v.Resolvers {
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeTXT)
		m.RecursionDesired = true
		r, _, err := c.ExchangeContext(ctx, m, res)
		if err == nil && r.Truncated {
			tc := &dns.Client{Net: "tcp", Timeout: v.Timeout}
			r, _, err = tc.ExchangeContext(ctx, m, res)
		}
		if err != nil || r == nil {
			continue
		}
		responded++
		for _, rr := range r.Answer {
			if t, ok := rr.(*dns.TXT); ok && strings.TrimSpace(strings.Join(t.Txt, "")) == want {
				found++
				break
			}
		}
	}
	if responded == 0 {
		return Result{Detail: "aucun résolveur n'a répondu"}
	}
	detail := fmt.Sprintf("jeton trouvé via %d résolveur(s) sur %d", found, responded)
	if found*2 > responded {
		return Result{OK: true, Detail: detail}
	}
	if found == 0 {
		detail = fmt.Sprintf("enregistrement TXT %s introuvable (%d résolveur(s) interrogé(s))", TXTName(a.Host), responded)
	}
	return Result{Detail: detail}
}

func (v Verifier) wellKnown(ctx context.Context, a Asset, allow []netip.Prefix) Result {
	pol := netguard.Policy{Allowlist: allow}
	if p, ok := Prefix(a); ok {
		if a.Kind == "cidr" {
			return Result{Detail: "une plage CIDR se prouve par la liste blanche, pas par fichier"}
		}
		pol.Scope = []netip.Prefix{p}
	}
	cl := pol.Client(v.Timeout)
	schemes := []string{a.Scheme, "https", "http"}
	seen := map[string]bool{}
	var lastErr string
	for _, sc := range schemes {
		if sc == "" || seen[sc] {
			continue
		}
		seen[sc] = true
		host := a.Host
		if a.Port > 0 {
			host = net.JoinHostPort(a.Host, fmt.Sprint(a.Port))
		} else if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		u := sc + "://" + host + WellKnownPath(a.ID)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		resp, err := cl.Do(req)
		if err != nil {
			lastErr = err.Error()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Sprintf("%s : HTTP %d", u, resp.StatusCode)
			continue
		}
		if strings.Contains(string(body), a.Token) {
			ips, _ := pol.Resolve(ctx, a.Host)
			out := make([]string, 0, len(ips))
			for _, ip := range ips {
				out = append(out, ip.String())
			}
			return Result{OK: true, Detail: "jeton trouvé dans " + u, ResolvedIPs: out}
		}
		lastErr = fmt.Sprintf("%s : HTTP 200 mais jeton différent", u)
	}
	return Result{Detail: lastErr}
}
