package canary

import (
	"bytes"
	"strings"
	"testing"
)

func signer(t *testing.T) *Signer {
	s, err := NewSigner(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestTokenBoundToAssetAndCheck(t *testing.T) {
	s := signer(t)
	tok := s.New(12, 345)
	if !LooksLikeToken(tok) {
		t.Fatalf("jeton mal formé : %q", tok)
	}
	if !s.Verify(tok, 12, 345) {
		t.Fatal("jeton valide refusé")
	}
	if s.Verify(tok, 13, 345) || s.Verify(tok, 12, 346) {
		t.Fatal("jeton accepté pour un autre asset ou un autre check")
	}
	if s.Verify(strings.ToUpper(tok), 12, 345) == false {
		t.Fatal("la casse ne doit pas compter (randomisation 0x20 des résolveurs)")
	}
	other, _ := NewSigner(bytes.Repeat([]byte{8}, 32))
	if other.Verify(tok, 12, 345) {
		t.Fatal("jeton accepté avec une autre clé")
	}
	// Un jeton forgé (bonne forme, mauvaise signature) est refusé.
	forged := "aaaaaaaaaaaaaaaaaaaa"
	if s.Verify(forged, 12, 345) {
		t.Fatal("jeton forgé accepté")
	}
}

func TestTokensAreUnique(t *testing.T) {
	s := signer(t)
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		tok := s.New(1, 1)
		if seen[tok] {
			t.Fatal("collision de jetons")
		}
		seen[tok] = true
	}
}

func TestParse(t *testing.T) {
	zone := "c.opencvec.exemple.fr"
	tok := signer(t).New(1, 2)
	cases := []struct {
		name      string
		inZone    bool
		tok, pt   string
	}{
		{"p3." + tok + "." + zone + ".", true, tok, "p3"},
		{strings.ToUpper(tok) + ".C.OPENCVEC.EXEMPLE.FR", true, tok, ""},
		{"x.y." + tok + "." + zone, true, tok, "y"},
		{"test." + zone, true, "", ""},
		{zone, true, "", ""},
		{"evil-" + zone, false, "", ""},
		{tok + ".exemple.fr", false, "", ""},
	}
	for _, c := range cases {
		p, ok := Parse(c.name, zone)
		if ok != c.inZone || p.Token != c.tok || p.Point != c.pt {
			t.Errorf("Parse(%q) = %+v, %v ; attendu jeton %q point %q zone %v", c.name, p, ok, c.tok, c.pt, c.inZone)
		}
	}
	if Host("p1", tok, zone) != "p1."+tok+"."+zone {
		t.Fatal("Host incorrect")
	}
}
