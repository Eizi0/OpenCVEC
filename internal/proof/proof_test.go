package proof

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// fakeDNS sert un enregistrement TXT donné.
func fakeDNS(t *testing.T, name, value string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if strings.EqualFold(r.Question[0].Name, dns.Fqdn(name)) {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{value}})
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestTXTProof(t *testing.T) {
	good := fakeDNS(t, "_opencvec.shop.exemple.fr", "opencvec-verif=ABCD-EFGH")
	bad := fakeDNS(t, "_opencvec.shop.exemple.fr", "opencvec-verif=AUTRE")
	a := Asset{ID: 1, Host: "shop.exemple.fr", Kind: "domain", Method: "dns_txt", Token: "ABCD-EFGH"}

	if r := (Verifier{Resolvers: []string{good, good}}).Verify(context.Background(), a, nil); !r.OK {
		t.Fatalf("preuve valide refusée : %s", r.Detail)
	}
	if r := (Verifier{Resolvers: []string{good, bad, bad}}).Verify(context.Background(), a, nil); r.OK {
		t.Fatal("minorité de résolveurs acceptée")
	}
	if r := (Verifier{Resolvers: []string{bad}}).Verify(context.Background(), a, nil); r.OK {
		t.Fatal("jeton différent accepté")
	}
}

func TestWellKnownProof(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/opencvec-7.txt" {
			w.Write([]byte("TOKEN-OK\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	p, _ := strconv.Atoi(port)
	a := Asset{ID: 7, Host: host, Kind: "ip", Scheme: "http", Port: p, Method: "well_known", Token: "TOKEN-OK"}

	// 127.0.0.1 n'est joignable que si un administrateur l'a autorisé.
	if r := (Verifier{}).Verify(context.Background(), a, nil); r.OK {
		t.Fatal("boucle locale contactée sans liste blanche")
	}
	allow := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	if r := (Verifier{}).Verify(context.Background(), a, allow); !r.OK {
		t.Fatalf("preuve valide refusée : %s", r.Detail)
	}
	a.Token = "AUTRE"
	if r := (Verifier{}).Verify(context.Background(), a, allow); r.OK {
		t.Fatal("jeton différent accepté")
	}
}

func TestAllowlistProof(t *testing.T) {
	allow := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}
	ok := Asset{Host: "10.20.0.0/24", Kind: "cidr", Method: "allowlist"}
	if r := (Verifier{}).Verify(context.Background(), ok, allow); !r.OK {
		t.Fatal(r.Detail)
	}
	wider := Asset{Host: "10.0.0.0/8", Kind: "cidr", Method: "allowlist"}
	if r := (Verifier{}).Verify(context.Background(), wider, allow); r.OK {
		t.Fatal("plage plus large que la liste blanche acceptée")
	}
	if r := (Verifier{}).Verify(context.Background(), Asset{Host: "10.30.0.1", Kind: "ip", Method: "allowlist"}, allow); r.OK {
		t.Fatal("IP hors liste blanche acceptée")
	}
}

func TestTokenFormat(t *testing.T) {
	tok := NewToken()
	if len(tok) != 19 || strings.Count(tok, "-") != 3 {
		t.Fatalf("jeton mal formé : %q", tok)
	}
}
