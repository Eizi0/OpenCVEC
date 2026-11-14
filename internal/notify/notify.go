// Package notify envoie les alertes d'OpenCVEC par webhook (JSON, Slack, Teams) et par e-mail.
package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Eizi0/OpenCVEC/internal/secrets"
)

// Types d'événements.
const (
	KindHoneytoken = "honeytoken" // canari fichier lu hors d'un check
	KindProved     = "proved"     // vulnérabilité prouvée
	KindProbable   = "probable"   // version vulnérable ou surface exposée
	KindSchedule   = "schedule"   // échec d'un check programmé
	KindTest       = "test"
)

// Config est la configuration des notifications (réglage « notifications »).
type Config struct {
	WebhookURL    string `json:"webhook_url"`
	WebhookFormat string `json:"webhook_format"` // json, slack, teams
	EmailTo       string `json:"email_to"`       // adresses séparées par des virgules
	SMTPHost      string `json:"smtp_host"`
	SMTPPort      int    `json:"smtp_port"`
	SMTPSecurity  string `json:"smtp_security"` // starttls, tls, none
	SMTPUser      string `json:"smtp_user"`
	SMTPPassword  string `json:"smtp_password"` // chiffré au repos
	SMTPFrom      string `json:"smtp_from"`
	OnHoneytoken  bool   `json:"on_honeytoken"`
	OnProved      bool   `json:"on_proved"`
	OnProbable    bool   `json:"on_probable"`
	OnSchedule    bool   `json:"on_schedule"`
}

// Defaults : alertes importantes activées, aucun canal configuré.
var Defaults = Config{WebhookFormat: "json", SMTPPort: 587, SMTPSecurity: "starttls", OnHoneytoken: true, OnProved: true, OnSchedule: true}

// Validate contrôle la configuration.
func (c Config) Validate() error {
	if c.WebhookURL != "" {
		u, err := url.Parse(c.WebhookURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return errors.New("webhook : URL http(s) attendue")
		}
	}
	switch c.WebhookFormat {
	case "json", "slack", "teams":
	default:
		return errors.New("format du webhook : json, slack ou teams")
	}
	if c.EmailTo != "" {
		if c.SMTPHost == "" || c.SMTPFrom == "" {
			return errors.New("e-mail : serveur SMTP et expéditeur obligatoires")
		}
		for _, a := range splitAddrs(c.EmailTo) {
			if !strings.Contains(a, "@") || strings.ContainsAny(a, "\r\n") {
				return fmt.Errorf("adresse invalide : %q", a)
			}
		}
	}
	if strings.ContainsAny(c.SMTPFrom+c.SMTPHost+c.SMTPUser, "\r\n") {
		return errors.New("caractères de fin de ligne interdits")
	}
	if c.SMTPPort < 0 || c.SMTPPort > 65535 {
		return errors.New("port SMTP invalide")
	}
	switch c.SMTPSecurity {
	case "starttls", "tls", "none":
	default:
		return errors.New("sécurité SMTP : starttls, tls ou none")
	}
	return nil
}

func splitAddrs(s string) []string {
	var out []string
	for _, a := range strings.Split(s, ",") {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	return out
}

// Event est une notification.
type Event struct {
	Kind  string    `json:"event"`
	Title string    `json:"title"`
	Text  string    `json:"text"`
	Link  string    `json:"url,omitempty"`
	At    time.Time `json:"at"`
}

// Notifier lit la configuration et envoie les événements.
type Notifier struct {
	DB        *pgxpool.Pool
	Box       *secrets.Box
	PublicURL string
	Log       *slog.Logger
	// HTTP sert aux webhooks (défaut : client sans redirection, délai 10 s).
	HTTP *http.Client
}

// Load lit la configuration (mot de passe SMTP déchiffré).
func (n *Notifier) Load(ctx context.Context) (Config, error) {
	c := Defaults
	var raw []byte
	err := n.DB.QueryRow(ctx, `SELECT value FROM settings WHERE key = 'notifications'`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return Defaults, err
	}
	if c.SMTPPassword != "" {
		if c.SMTPPassword, err = n.Box.Open(c.SMTPPassword); err != nil {
			return c, err
		}
	}
	return c, nil
}

// Save enregistre la configuration (mot de passe SMTP chiffré).
func (n *Notifier) Save(ctx context.Context, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	sealed, err := n.Box.Seal(c.SMTPPassword)
	if err != nil {
		return err
	}
	c.SMTPPassword = sealed
	b, _ := json.Marshal(c)
	_, err = n.DB.Exec(ctx, `INSERT INTO settings (key, value) VALUES ('notifications', $1)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, b)
	return err
}

func (c Config) wants(kind string) bool {
	switch kind {
	case KindHoneytoken:
		return c.OnHoneytoken
	case KindProved:
		return c.OnProved
	case KindProbable:
		return c.OnProbable
	case KindSchedule:
		return c.OnSchedule
	}
	return true
}

// Send envoie un événement en arrière-plan sur les canaux configurés, s'il est souhaité.
func (n *Notifier) Send(ev Event) {
	if n == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c, err := n.Load(ctx)
		if err != nil {
			n.Log.Error("notifications : configuration illisible", "err", err)
			return
		}
		if !c.wants(ev.Kind) {
			return
		}
		for _, err := range n.Deliver(ctx, c, ev) {
			n.Log.Error("notification non envoyée", "événement", ev.Kind, "err", err)
		}
	}()
}

// Deliver envoie immédiatement sur chaque canal configuré et renvoie les erreurs par canal.
func (n *Notifier) Deliver(ctx context.Context, c Config, ev Event) map[string]error {
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	if ev.Link != "" && strings.HasPrefix(ev.Link, "/") {
		ev.Link = strings.TrimRight(n.PublicURL, "/") + ev.Link
	}
	errs := map[string]error{}
	if c.WebhookURL != "" {
		if err := n.webhook(ctx, c, ev); err != nil {
			errs["webhook"] = err
		}
	}
	if c.EmailTo != "" {
		if err := n.email(c, ev); err != nil {
			errs["email"] = err
		}
	}
	return errs
}

func (n *Notifier) webhook(ctx context.Context, c Config, ev Event) error {
	text := "*" + ev.Title + "*\n" + ev.Text
	if ev.Link != "" {
		text += "\n" + ev.Link
	}
	var body any = ev
	switch c.WebhookFormat {
	case "slack":
		body = map[string]string{"text": text}
	case "teams":
		body = map[string]string{"text": strings.ReplaceAll(text, "\n", "\n\n")}
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.WebhookURL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "OpenCVEC")
	cl := n.HTTP
	if cl == nil {
		cl = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook : HTTP %d", resp.StatusCode)
	}
	return nil
}

func (n *Notifier) email(c Config, ev Event) error {
	to := splitAddrs(c.EmailTo)
	port := c.SMTPPort
	if port == 0 {
		port = map[string]int{"tls": 465, "starttls": 587, "none": 25}[c.SMTPSecurity]
	}
	addr := net.JoinHostPort(c.SMTPHost, strconv.Itoa(port))
	var msg bytes.Buffer
	fmt.Fprintf(&msg, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\nAuto-Submitted: auto-generated\r\n\r\n",
		c.SMTPFrom, strings.Join(to, ", "), mime.QEncoding.Encode("utf-8", "[OpenCVEC] "+ev.Title), ev.At.Format(time.RFC1123Z))
	msg.WriteString(strings.ReplaceAll(ev.Text, "\n", "\r\n"))
	if ev.Link != "" {
		msg.WriteString("\r\n\r\n" + ev.Link)
	}
	msg.WriteString("\r\n")

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	var err error
	if c.SMTPSecurity == "tls" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: c.SMTPHost})
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	cl, err := smtp.NewClient(conn, c.SMTPHost)
	if err != nil {
		conn.Close()
		return err
	}
	defer cl.Close()
	if c.SMTPSecurity == "starttls" {
		if err := cl.StartTLS(&tls.Config{ServerName: c.SMTPHost}); err != nil {
			return fmt.Errorf("STARTTLS : %w", err)
		}
	}
	if c.SMTPUser != "" {
		if err := cl.Auth(smtp.PlainAuth("", c.SMTPUser, c.SMTPPassword, c.SMTPHost)); err != nil {
			return fmt.Errorf("authentification SMTP : %w", err)
		}
	}
	if err := cl.Mail(c.SMTPFrom); err != nil {
		return err
	}
	for _, a := range to {
		if err := cl.Rcpt(a); err != nil {
			return fmt.Errorf("destinataire %s : %w", a, err)
		}
	}
	w, err := cl.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg.Bytes()); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return cl.Quit()
}
