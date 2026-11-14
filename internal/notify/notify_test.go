package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebhookFormats(t *testing.T) {
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		got = append(got, m)
	}))
	defer srv.Close()
	n := &Notifier{PublicURL: "https://opencvec.exemple.fr"}
	ev := Event{Kind: KindHoneytoken, Title: "Canari lu", Text: "erp.exemple.fr", Link: "/callbacks"}
	for _, f := range []string{"json", "slack", "teams"} {
		c := Defaults
		c.WebhookURL, c.WebhookFormat = srv.URL, f
		if errs := n.Deliver(context.Background(), c, ev); len(errs) > 0 {
			t.Fatalf("%s : %v", f, errs)
		}
	}
	if got[0]["event"] != "honeytoken" || got[0]["url"] != "https://opencvec.exemple.fr/callbacks" {
		t.Fatalf("JSON : %v", got[0])
	}
	if !strings.Contains(got[1]["text"].(string), "*Canari lu*") || got[2]["text"] == nil {
		t.Fatalf("Slack/Teams : %v %v", got[1], got[2])
	}
}

// fakeSMTP est un serveur SMTP minimal (sans TLS) qui capture le message reçu.
func fakeSMTP(t *testing.T) (string, chan string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		io.WriteString(c, "220 test\r\n")
		var data strings.Builder
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if line == ".\r\n" {
					inData = false
					out <- data.String()
					io.WriteString(c, "250 ok\r\n")
					continue
				}
				data.WriteString(line)
				continue
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				io.WriteString(c, "250 test\r\n")
			case cmd == "DATA":
				inData = true
				io.WriteString(c, "354 go\r\n")
			case cmd == "QUIT":
				io.WriteString(c, "221 bye\r\n")
				return
			default:
				io.WriteString(c, "250 ok\r\n")
			}
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), out
}

func TestEmail(t *testing.T) {
	addr, out := fakeSMTP(t)
	host, port, _ := net.SplitHostPort(addr)
	c := Defaults
	c.EmailTo, c.SMTPHost, c.SMTPFrom, c.SMTPSecurity = "rssi@exemple.fr, soc@exemple.fr", host, "opencvec@exemple.fr", "none"
	c.SMTPPort = atoi(port)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	n := &Notifier{PublicURL: "https://opencvec.exemple.fr"}
	if errs := n.Deliver(context.Background(), c, Event{Kind: KindProved, Title: "Vulnérabilité prouvée", Text: "Log4Shell sur erp", Link: "/checks/3"}); len(errs) > 0 {
		t.Fatal(errs)
	}
	msg := <-out
	if !strings.Contains(msg, "To: rssi@exemple.fr, soc@exemple.fr") || !strings.Contains(msg, "Subject: =?utf-8?q?") || !strings.Contains(msg, "https://opencvec.exemple.fr/checks/3") {
		t.Fatalf("message : %s", msg)
	}
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

func TestWebhookRefusesMetadata(t *testing.T) {
	c := Defaults
	c.WebhookURL = "http://169.254.169.254/latest/meta-data/"
	errs := (&Notifier{}).Deliver(context.Background(), c, Event{Kind: KindTest, Title: "x"})
	if errs["webhook"] == nil || !strings.Contains(errs["webhook"].Error(), "refusée") {
		t.Fatalf("métadonnées cloud non bloquées : %v", errs)
	}
}

func TestValidate(t *testing.T) {
	bad := []Config{
		{WebhookURL: "ftp://x", WebhookFormat: "json", SMTPSecurity: "starttls"},
		{WebhookFormat: "xml", SMTPSecurity: "starttls"},
		{WebhookFormat: "json", SMTPSecurity: "starttls", EmailTo: "a@b.fr"},
		{WebhookFormat: "json", SMTPSecurity: "starttls", EmailTo: "a@b.fr\r\nBcc: x@y", SMTPHost: "h", SMTPFrom: "f@x"},
	}
	for i, c := range bad {
		if c.Validate() == nil {
			t.Errorf("configuration %d acceptée à tort", i)
		}
	}
}
