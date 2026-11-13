package receiver

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/Eizi0/OpenCVEC/internal/canary"
)

// DNSHandler répond en serveur autoritaire pour la zone canari et transmet chaque requête au corrélateur.
type DNSHandler struct {
	C      *Correlator
	Zone   string
	NSName string
	IP     net.IP
}

func (h *DNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	if len(r.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(m)
		return
	}
	q := r.Question[0]
	name := strings.ToLower(q.Name)
	zone := dns.Fqdn(h.Zone)
	if name != zone && !strings.HasSuffix(name, "."+zone) {
		m.Authoritative = false
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}
	src := hostOnly(w.RemoteAddr().String())
	if h.C != nil {
		raw := fmt.Sprintf(";; QUESTION SECTION:\n;%s\tIN\t%s\n;; FROM %s (%s)", q.Name, dns.TypeToString[q.Qtype], w.RemoteAddr(), w.RemoteAddr().Network())
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := h.C.Record(ctx, Event{Proto: "dns", QType: dns.TypeToString[q.Qtype], QName: q.Name, Source: src, Raw: raw}); err != nil && h.C.Log != nil {
				h.C.Log.Error("enregistrement d'un callback DNS", "err", err)
			}
		}()
	}
	soa := &dns.SOA{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:  dns.Fqdn(h.NSName), Mbox: "hostmaster." + zone,
		Serial: 2026111401, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 0,
	}
	ttl := uint32(0) // pas de cache : chaque check doit produire sa propre requête
	if name == zone {
		ttl = 60
	}
	switch q.Qtype {
	case dns.TypeA, dns.TypeANY:
		if v4 := h.IP.To4(); v4 != nil {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: v4})
		}
	case dns.TypeAAAA:
		if h.IP.To4() == nil {
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}, AAAA: h.IP})
		}
	case dns.TypeSOA:
		if name == zone {
			m.Answer = append(m.Answer, soa)
		}
	case dns.TypeNS:
		if name == zone {
			m.Answer = append(m.Answer, &dns.NS{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: dns.Fqdn(h.NSName)})
		}
	}
	if len(m.Answer) == 0 {
		m.Ns = append(m.Ns, soa)
	}
	_ = w.WriteMsg(m)
}

// HTTPHandler enregistre toute requête HTTP adressée à un nom de la zone (ou portant un jeton dans le chemin).
func HTTPHandler(c *Correlator, zone string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(hostOnly(r.Host))
		name := host
		if _, ok := canary.Parse(host, zone); !ok || host == zone {
			// Jeton éventuellement placé dans le chemin : /<jeton>[/...]
			seg := strings.Split(strings.Trim(r.URL.Path, "/"), "/")[0]
			if canary.LooksLikeToken(strings.ToLower(seg)) {
				name = strings.ToLower(seg) + "." + zone
			} else {
				name = ""
			}
		}
		if name != "" {
			var sb strings.Builder
			fmt.Fprintf(&sb, "%s %s %s\nHost: %s\n", r.Method, truncate(r.URL.RequestURI(), 300), r.Proto, r.Host)
			keys := make([]string, 0, len(r.Header))
			for k := range r.Header {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(&sb, "%s: %s\n", k, truncate(strings.Join(r.Header[k], ", "), 200))
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 64<<10))
			if _, err := c.Record(r.Context(), Event{Proto: "http", QType: r.Method, QName: name, Source: hostOnly(r.RemoteAddr), Raw: sb.String()}); err != nil && c.Log != nil {
				c.Log.Error("enregistrement d'un callback HTTP", "err", err)
			}
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, "OpenCVEC canary receiver\n")
	})
}

// ServeDNS démarre les serveurs UDP et TCP ; ils s'arrêtent à l'annulation du contexte.
func ServeDNS(ctx context.Context, addr string, h dns.Handler) (func() error, error) {
	udp := &dns.Server{Addr: addr, Net: "udp", Handler: h}
	tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: h}
	errc := make(chan error, 2)
	started := make(chan struct{}, 2)
	udp.NotifyStartedFunc = func() { started <- struct{}{} }
	tcp.NotifyStartedFunc = func() { started <- struct{}{} }
	go func() { errc <- udp.ListenAndServe() }()
	go func() { errc <- tcp.ListenAndServe() }()
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case err := <-errc:
			_ = udp.Shutdown()
			_ = tcp.Shutdown()
			return nil, fmt.Errorf("écoute DNS sur %s : %w", addr, err)
		case <-time.After(5 * time.Second):
			return nil, fmt.Errorf("écoute DNS sur %s : délai dépassé", addr)
		}
	}
	return func() error {
		_ = udp.ShutdownContext(ctx)
		return tcp.ShutdownContext(ctx)
	}, nil
}
