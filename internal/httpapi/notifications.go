package httpapi

import (
	"net/http"
	"strings"

	"github.com/Eizi0/OpenCVEC/internal/notify"
)

// Le mot de passe SMTP n'est jamais renvoyé : ce marqueur signifie « inchangé ».
const keepSecret = "••••••••"

func (s *Server) getNotifications(w http.ResponseWriter, r *http.Request, u *User) {
	c, err := s.Notifier.Load(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if c.SMTPPassword != "" {
		c.SMTPPassword = keepSecret
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) readNotifications(w http.ResponseWriter, r *http.Request) (notify.Config, bool) {
	var c notify.Config
	if !readJSON(w, r, &c) {
		return c, false
	}
	if c.SMTPPassword == keepSecret {
		cur, err := s.Notifier.Load(r.Context())
		if err != nil {
			s.fail(w, r, err)
			return c, false
		}
		c.SMTPPassword = cur.SMTPPassword
	}
	c.WebhookURL = strings.TrimSpace(c.WebhookURL)
	if err := c.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return c, false
	}
	return c, true
}

func (s *Server) putNotifications(w http.ResponseWriter, r *http.Request, u *User) {
	c, ok := s.readNotifications(w, r)
	if !ok {
		return
	}
	if err := s.Notifier.Save(r.Context(), c); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var ch []string
	if c.WebhookURL != "" {
		ch = append(ch, "webhook "+c.WebhookFormat)
	}
	if c.EmailTo != "" {
		ch = append(ch, "e-mail")
	}
	if len(ch) == 0 {
		ch = append(ch, "aucun canal")
	}
	s.audit(r, u, "Réglages modifiés", "notifications : "+strings.Join(ch, ", "))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// testNotifications envoie un message de test avec la configuration fournie (non enregistrée).
func (s *Server) testNotifications(w http.ResponseWriter, r *http.Request, u *User) {
	c, ok := s.readNotifications(w, r)
	if !ok {
		return
	}
	errs := s.Notifier.Deliver(r.Context(), c, notify.Event{Kind: notify.KindTest, Title: "Test des notifications",
		Text: "Ce message confirme que les notifications d'OpenCVEC arrivent bien (demandé par " + u.Email + ").", Link: "/admin"})
	out := map[string]string{}
	if c.WebhookURL != "" {
		out["webhook"] = "ok"
	}
	if c.EmailTo != "" {
		out["email"] = "ok"
	}
	for k, e := range errs {
		out[k] = e.Error()
	}
	if len(out) == 0 {
		writeErr(w, http.StatusBadRequest, "aucun canal configuré (webhook ou e-mail)")
		return
	}
	writeJSON(w, http.StatusOK, out)
}
