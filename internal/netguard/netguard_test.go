package netguard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestPolicy(t *testing.T) {
	pub := netip.MustParseAddr("203.0.113.24") // plage de documentation, traitée comme publique
	cases := []struct {
		name string
		p    Policy
		a    string
		ok   bool
	}{
		{"public autorisé", Policy{}, "8.8.8.8", true},
		{"boucle locale refusée", Policy{}, "127.0.0.1", false},
		{"métadonnées cloud refusées", Policy{}, "169.254.169.254", false},
		{"privé refusé", Policy{}, "10.1.2.3", false},
		{"IPv6 mappée refusée", Policy{}, "::ffff:127.0.0.1", false},
		{"privé sur liste blanche", Policy{Allowlist: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}}, "10.1.2.3", true},
		{"privé hors liste blanche", Policy{Allowlist: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}}, "10.2.0.1", false},
		{"hors périmètre de l'asset", Policy{Scope: []netip.Prefix{netip.MustParsePrefix("8.8.4.0/24")}}, "8.8.8.8", false},
		{"dans le périmètre de l'asset", Policy{Scope: []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")}}, "8.8.8.8", true},
	}
	for _, c := range cases {
		if got := c.p.Allowed(netip.MustParseAddr(c.a)); got != c.ok {
			t.Errorf("%s : Allowed(%s) = %v", c.name, c.a, got)
		}
	}
	if !IsPublic(pub) {
		t.Fatal("203.0.113.24 devrait être considérée publique")
	}
}

func TestClientRefusesLoopbackUnlessAllowlisted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()

	_, err := Policy{}.Client(2 * time.Second).Get(srv.URL)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("connexion vers 127.0.0.1 non bloquée : %v", err)
	}
	p := Policy{Allowlist: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	resp, err := p.Client(2 * time.Second).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("la redirection ne doit pas être suivie, statut %d", resp.StatusCode)
	}
	if _, err := p.Resolve(context.Background(), "169.254.169.254"); !errors.Is(err, ErrForbidden) {
		t.Fatal("métadonnées cloud résolues malgré la politique")
	}
}
