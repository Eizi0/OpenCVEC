// Commande opencvec : serveur (interface, API, récepteur canari) et outils d'administration.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Eizi0/OpenCVEC/internal/audit"
	"github.com/Eizi0/OpenCVEC/internal/auth"
	"github.com/Eizi0/OpenCVEC/internal/canary"
	"github.com/Eizi0/OpenCVEC/internal/config"
	"github.com/Eizi0/OpenCVEC/internal/httpapi"
	"github.com/Eizi0/OpenCVEC/internal/maintenance"
	"github.com/Eizi0/OpenCVEC/internal/plugin"
	"github.com/Eizi0/OpenCVEC/internal/proof"
	"github.com/Eizi0/OpenCVEC/internal/receiver"
	"github.com/Eizi0/OpenCVEC/internal/runner"
	"github.com/Eizi0/OpenCVEC/internal/secrets"
	"github.com/Eizi0/OpenCVEC/internal/settings"
	"github.com/Eizi0/OpenCVEC/internal/store"
	officialplugins "github.com/Eizi0/OpenCVEC/plugins"
	"github.com/Eizi0/OpenCVEC/web"
)

// version est injectée à la compilation (-ldflags "-X main.version=v0.1.0").
var version = "dev"

const usage = `OpenCVEC : vérification de CVE par canari, auto-hébergée.

Usage :
  opencvec serve         démarre l'interface, l'API et le récepteur canari
  opencvec migrate       applique les migrations de la base
  opencvec healthcheck   vérifie que le serveur répond (sonde Docker)
  opencvec reset-admin <e-mail>
                         crée ou réinitialise un administrateur (mot de passe affiché une fois)
  opencvec plugin ...    outils de création et de signature de plugins (opencvec plugin)

Configuration : variables OPENCVEC_* (voir README.md).
`

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "migrate":
		err = withStore(func(ctx context.Context, st *store.Store, _ config.Config) error { return st.Migrate(ctx) })
	case "healthcheck":
		err = healthcheck()
	case "reset-admin":
		if len(os.Args) < 3 {
			err = errors.New("usage : opencvec reset-admin <e-mail>")
			break
		}
		err = withStore(func(ctx context.Context, st *store.Store, _ config.Config) error {
			if err := st.Migrate(ctx); err != nil {
				return err
			}
			return resetAdmin(ctx, st.Pool, os.Args[2])
		})
	case "plugin":
		err = pluginCmd(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("OpenCVEC", version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "erreur :", err)
		os.Exit(1)
	}
}

func withStore(fn func(context.Context, *store.Store, config.Config) error) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()
	return fn(ctx, st, cfg)
}

func healthcheck() error {
	addr := os.Getenv("OPENCVEC_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + addr + "/api/health")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("statut %d", resp.StatusCode)
	}
	return nil
}

func resetAdmin(ctx context.Context, db *pgxpool.Pool, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	pw := strings.TrimSpace(os.Getenv("OPENCVEC_ADMIN_PASSWORD"))
	if pw == "" {
		b := make([]byte, 12)
		_, _ = rand.Read(b)
		pw = base64.RawURLEncoding.EncodeToString(b)
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return err
	}
	_, err = db.Exec(ctx, `INSERT INTO users (email, name, role, password_hash) VALUES ($1, 'Administrateur', 'admin', $2)
		ON CONFLICT (email) DO UPDATE SET password_hash = EXCLUDED.password_hash, role = 'admin', disabled = false,
		totp_enabled = false, totp_secret = ''`, email, hash)
	if err != nil {
		return err
	}
	_, _ = db.Exec(ctx, `DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = $1)`, email)
	al := &audit.Log{DB: db}
	_ = al.Write(ctx, nil, "système", "Accès réinitialisé", email+" : administrateur réinitialisé en ligne de commande", "")
	fmt.Printf("Administrateur %s\nMot de passe : %s\n", email, pw)
	return nil
}

// bootstrap crée le premier administrateur si la base n'en contient aucun.
func bootstrap(ctx context.Context, db *pgxpool.Pool, cfg config.Config, log *slog.Logger) error {
	var n int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	pw := cfg.BootstrapAdminPassword
	generated := pw == ""
	if generated {
		b := make([]byte, 12)
		_, _ = rand.Read(b)
		pw = base64.RawURLEncoding.EncodeToString(b)
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return err
	}
	if _, err := db.Exec(ctx, `INSERT INTO users (email, name, role, password_hash) VALUES ($1, 'Administrateur', 'admin', $2)`,
		strings.ToLower(cfg.BootstrapAdminEmail), hash); err != nil {
		return err
	}
	al := &audit.Log{DB: db}
	_ = al.Write(ctx, nil, "système", "Utilisateur créé", cfg.BootstrapAdminEmail+" · premier administrateur", "")
	if generated {
		log.Warn("premier administrateur créé : notez ce mot de passe, il ne sera plus affiché",
			"email", cfg.BootstrapAdminEmail, "mot_de_passe", pw)
	} else {
		log.Info("premier administrateur créé", "email", cfg.BootstrapAdminEmail)
	}
	return nil
}

// canaryKey lit (ou crée) la clé HMAC des canaris, chiffrée au repos.
func canaryKey(ctx context.Context, db *pgxpool.Pool, box *secrets.Box) ([]byte, error) {
	var raw string
	err := db.QueryRow(ctx, `SELECT value #>> '{}' FROM settings WHERE key = 'canary_key'`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		sealed, err := box.Seal(base64.StdEncoding.EncodeToString(k))
		if err != nil {
			return nil, err
		}
		if _, err := db.Exec(ctx, `INSERT INTO settings (key, value) VALUES ('canary_key', to_jsonb($1::text)) ON CONFLICT DO NOTHING`, sealed); err != nil {
			return nil, err
		}
		return canaryKey(ctx, db, box)
	}
	if err != nil {
		return nil, err
	}
	plain, err := box.Open(raw)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(plain)
}

func serve() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	var h slog.Handler = slog.NewTextHandler(os.Stdout, nil)
	if cfg.LogFormat == "json" {
		h = slog.NewJSONHandler(os.Stdout, nil)
	}
	log := slog.New(h)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	box, err := secrets.New(cfg.SecretKey)
	if err != nil {
		return err
	}
	if !box.Enabled() {
		log.Warn("OPENCVEC_SECRET_KEY absente : secrets TOTP et clé des canaris stockés en clair (à éviter en production)")
	}
	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	if err := bootstrap(ctx, st.Pool, cfg, log); err != nil {
		return err
	}
	key, err := canaryKey(ctx, st.Pool, box)
	if err != nil {
		return fmt.Errorf("clé des canaris : %w", err)
	}
	signer, err := canary.NewSigner(key)
	if err != nil {
		return err
	}

	corr := &receiver.Correlator{DB: st.Pool, Signer: signer, Zone: cfg.CanaryZone, Log: log}
	auditLog := &audit.Log{DB: st.Pool}
	corr.OnHoneytoken = func(assetID int64, ev receiver.Event) {
		var host string
		_ = st.Pool.QueryRow(context.Background(), `SELECT host FROM assets WHERE id = $1`, assetID).Scan(&host)
		_ = auditLog.Write(context.Background(), nil, "récepteur", "Alerte canari fichier",
			fmt.Sprintf("%s : le contenu du canari fichier est revenu hors de tout check (%s %s depuis %s). Compromission probable de l'asset.", host, ev.Proto, ev.QType, ev.Source), ev.Source)
	}
	plugins := &plugin.Store{DB: st.Pool, Log: log, Official: plugin.OfficialPublicKey}
	if err := plugins.EnsureOfficial(ctx); err != nil {
		return err
	}
	if done, err := plugins.Preinstall(ctx, officialplugins.FS); err != nil {
		log.Error("préinstallation des plugins officiels", "err", err)
	} else if len(done) > 0 {
		log.Info("plugins officiels installés ou mis à jour", "plugins", strings.Join(done, ", "))
		_ = auditLog.Write(ctx, nil, "système", "Plugin installé", "préinstallation : "+strings.Join(done, ", "), "")
	}
	if gs, err := settings.Load(ctx, st.Pool); err == nil {
		if err := plugins.Load(ctx, gs.AllowUnsignedPlugins); err != nil {
			log.Error("chargement des plugins", "err", err)
		}
	}
	srv := &httpapi.Server{
		Cfg: cfg, DB: st.Pool, Web: web.FS(), Log: log, Secrets: box, Version: version,
		Audit:    auditLog,
		Corr:     corr,
		Plugins:  plugins,
		Verifier: proof.Verifier{Resolvers: cfg.ProofResolvers},
	}

	// Récepteur DNS.
	if cfg.DNSAddr != "off" {
		dh := &receiver.DNSHandler{C: corr, Zone: cfg.CanaryZone, NSName: cfg.NSName, IP: net.ParseIP(cfg.CanaryIP)}
		shutdown, err := receiver.ServeDNS(ctx, cfg.DNSAddr, dh)
		if err != nil {
			log.Error("récepteur DNS indisponible", "err", err)
		} else {
			srv.DNSUp = true
			defer shutdown() //nolint:errcheck
			log.Info("récepteur DNS autoritaire", "addr", cfg.DNSAddr, "zone", cfg.CanaryZone)
		}
	}
	// Récepteur HTTP.
	var canaryHTTP *http.Server
	if cfg.CanaryHTTPAddr != "off" {
		canaryHTTP = &http.Server{Addr: cfg.CanaryHTTPAddr, Handler: receiver.HTTPHandler(corr, cfg.CanaryZone),
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 20 * time.Second}
		ln, err := net.Listen("tcp", cfg.CanaryHTTPAddr)
		if err != nil {
			log.Error("récepteur HTTP indisponible", "err", err)
		} else {
			srv.HTTPUp = true
			go func() { _ = canaryHTTP.Serve(ln) }()
			log.Info("récepteur HTTP", "addr", cfg.CanaryHTTPAddr)
		}
	}

	run := &runner.Runner{DB: st.Pool, Corr: corr, Signer: signer, Zone: cfg.CanaryZone, Log: log}
	if err := run.Start(ctx, cfg.Workers); err != nil {
		return err
	}
	srv.Runner = run
	go maintenance.Run(ctx, st.Pool, log)

	api := &http.Server{Addr: cfg.Addr, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- api.ListenAndServe() }()
	log.Info("OpenCVEC démarré", "version", version, "addr", cfg.Addr, "zone_canari", cfg.CanaryZone)
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if canaryHTTP != nil {
		_ = canaryHTTP.Shutdown(sctx)
	}
	return api.Shutdown(sctx)
}
