// Package config lit la configuration d'OpenCVEC depuis les variables d'environnement.
package config

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// Config regroupe tous les réglages du serveur.
type Config struct {
	// Addr est l'adresse d'écoute de l'interface web et de l'API.
	Addr string
	// DatabaseURL est la chaîne de connexion PostgreSQL.
	DatabaseURL string
	// SecretKey (32 octets en base64 ou hexadécimal) chiffre au repos les secrets TOTP
	// et la clé HMAC des canaris.
	SecretKey string

	// CanaryZone est la zone DNS déléguée au récepteur (ex. c.opencvec.exemple.fr).
	CanaryZone string
	// CanaryIP est l'adresse renvoyée pour tout nom de la zone (celle du récepteur HTTP).
	CanaryIP string
	// NSName est le nom du serveur de noms annoncé pour la zone (ex. ns1.opencvec.exemple.fr).
	NSName string
	// DNSAddr est l'adresse d'écoute du DNS autoritaire (UDP et TCP), « off » pour le désactiver.
	DNSAddr string
	// CanaryHTTPAddr est l'adresse d'écoute du récepteur HTTP des callbacks, « off » pour le désactiver.
	CanaryHTTPAddr string

	// ProofResolvers sont les résolveurs interrogés pour les preuves DNS TXT et l'auto-test.
	ProofResolvers []string

	// PublicURL est l'adresse de l'interface, utilisée dans les liens des notifications.
	PublicURL string

	// PluginRegistry est l'URL (https) du dossier contenant index.json et les plugins officiels.
	PluginRegistry string

	TrustProxy    bool
	SecureCookies bool
	RequireMFA    bool
	LogFormat     string
	Workers       int

	BootstrapAdminEmail    string
	BootstrapAdminPassword string
}

// Load lit l'environnement et applique des valeurs par défaut raisonnables.
func Load() (Config, error) {
	c := Config{
		Addr:                   env("OPENCVEC_ADDR", ":8080"),
		DatabaseURL:            os.Getenv("OPENCVEC_DATABASE_URL"),
		SecretKey:              os.Getenv("OPENCVEC_SECRET_KEY"),
		CanaryZone:             strings.ToLower(strings.Trim(env("OPENCVEC_CANARY_ZONE", "c.opencvec.local"), ".")),
		CanaryIP:               env("OPENCVEC_CANARY_IP", "127.0.0.1"),
		NSName:                 strings.ToLower(strings.Trim(os.Getenv("OPENCVEC_NS_NAME"), ".")),
		DNSAddr:                env("OPENCVEC_DNS_ADDR", ":5353"),
		CanaryHTTPAddr:         env("OPENCVEC_CANARY_HTTP_ADDR", ":8081"),
		ProofResolvers:         splitList(env("OPENCVEC_PROOF_RESOLVERS", "1.1.1.1:53,8.8.8.8:53,9.9.9.9:53")),
		PublicURL:              strings.TrimRight(env("OPENCVEC_PUBLIC_URL", "http://localhost:8080"), "/"),
		PluginRegistry:         env("OPENCVEC_PLUGIN_REGISTRY", "https://raw.githubusercontent.com/Eizi0/OpenCVEC/main/plugins/"),
		TrustProxy:             env("OPENCVEC_TRUST_PROXY", "false") == "true",
		SecureCookies:          env("OPENCVEC_SECURE_COOKIES", "false") == "true",
		RequireMFA:             env("OPENCVEC_REQUIRE_MFA", "false") == "true",
		LogFormat:              env("OPENCVEC_LOG_FORMAT", "text"),
		Workers:                4,
		BootstrapAdminEmail:    env("OPENCVEC_ADMIN_EMAIL", "admin@opencvec.local"),
		BootstrapAdminPassword: os.Getenv("OPENCVEC_ADMIN_PASSWORD"),
	}
	if c.NSName == "" {
		c.NSName = "ns1." + c.CanaryZone
	}
	if c.DatabaseURL == "" {
		return c, fmt.Errorf("OPENCVEC_DATABASE_URL est obligatoire (ex. postgres://opencvec:opencvec@localhost:5432/opencvec?sslmode=disable)")
	}
	if net.ParseIP(c.CanaryIP) == nil {
		return c, fmt.Errorf("OPENCVEC_CANARY_IP doit être une adresse IP (reçu %q)", c.CanaryIP)
	}
	if !strings.Contains(c.CanaryZone, ".") {
		return c, fmt.Errorf("OPENCVEC_CANARY_ZONE doit être un nom de domaine complet (reçu %q)", c.CanaryZone)
	}
	return c, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			if !strings.Contains(p, ":") || strings.Count(p, ":") > 1 && !strings.HasPrefix(p, "[") {
				p = net.JoinHostPort(p, "53")
			}
			out = append(out, p)
		}
	}
	return out
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
