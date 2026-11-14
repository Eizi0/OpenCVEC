// Package netguard limite les connexions sortantes d'OpenCVEC au périmètre prouvé.
//
// Toute requête vers une cible passe par un client dont le dialer vérifie l'adresse IP
// effectivement contactée (après résolution DNS) : un nom prouvé qui se met à pointer vers
// 127.0.0.1, un service de métadonnées cloud ou un réseau interne non autorisé est refusé
// (protection contre le rebinding DNS et l'usage d'OpenCVEC comme rebond).
package netguard

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// ErrForbidden signale une adresse hors du périmètre autorisé.
var ErrForbidden = errors.New("adresse hors du périmètre autorisé")

// Policy décrit les adresses joignables pour un asset.
type Policy struct {
	// Allowlist : plages autorisées par un administrateur (réseau interne, labo).
	Allowlist []netip.Prefix
	// Scope : si non vide, l'adresse doit appartenir à l'une de ces plages (asset IP ou CIDR).
	Scope []netip.Prefix
}

// alwaysDenied ne sont joignables que si un administrateur les a explicitement autorisées.
var special = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// IsPublic indique si une adresse est routable sur Internet (ni privée, ni locale, ni réservée).
func IsPublic(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() {
		return false
	}
	for _, p := range special {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

func inAny(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Allowed applique la politique à une adresse.
func (p Policy) Allowed(a netip.Addr) bool {
	a = a.Unmap()
	if len(p.Scope) > 0 && !inAny(a, p.Scope) {
		return false
	}
	return IsPublic(a) || inAny(a, p.Allowlist)
}

// Check renvoie une erreur explicite si l'adresse est refusée.
func (p Policy) Check(a netip.Addr) error {
	if p.Allowed(a) {
		return nil
	}
	if len(p.Scope) > 0 && !inAny(a.Unmap(), p.Scope) {
		return fmt.Errorf("%w : %s n'appartient pas à l'asset", ErrForbidden, a)
	}
	return fmt.Errorf("%w : %s est une adresse privée ou réservée absente de la liste blanche", ErrForbidden, a)
}

// Resolve résout un hôte et ne garde que les adresses autorisées (erreur si aucune).
func (p Policy) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		if err := p.Check(a); err != nil {
			return nil, err
		}
		return []netip.Addr{a.Unmap()}, nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("résolution de %s impossible : %w", host, err)
	}
	var ok []netip.Addr
	var firstErr error
	for _, a := range addrs {
		if err := p.Check(a); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		ok = append(ok, a.Unmap())
	}
	if len(ok) == 0 {
		if firstErr == nil {
			firstErr = fmt.Errorf("%w : aucune adresse pour %s", ErrForbidden, host)
		}
		return nil, firstErr
	}
	return ok, nil
}

// Dial ouvre une connexion confinée à la politique : l'adresse est résolue, chaque IP est
// vérifiée, puis la connexion est établie vers l'IP vérifiée (pas de seconde résolution).
func (p Policy) Dial(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := p.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: timeout}
	var lastErr error
	for _, ip := range ips {
		c, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// Client renvoie un client HTTP confiné à la politique : chaque connexion est vérifiée au moment
// de la numérotation, les redirections ne sont jamais suivies et les certificats ne sont pas
// vérifiés (les assets internes utilisent souvent des certificats auto-signés).
func (p Policy) Client(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return p.Dial(ctx, network, addr, timeout)
		},
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // assets internes auto-signés
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		DisableKeepAlives:     true,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout + 5*time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
