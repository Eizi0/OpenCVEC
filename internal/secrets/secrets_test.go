package secrets

import (
	"encoding/base64"
	"strings"
	"testing"
)

func key() string {
	return base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
}

func TestSealOpen(t *testing.T) {
	b, err := New(key())
	if err != nil {
		t.Fatal(err)
	}
	s1, _ := b.Seal("mot de passe SMTP")
	s2, _ := b.Seal("mot de passe SMTP")
	if !IsSealed(s1) || strings.Contains(s1, "SMTP") || s1 == s2 {
		t.Fatalf("chiffrement attendu, avec un nonce aléatoire : %q / %q", s1, s2)
	}
	if p, err := b.Open(s1); err != nil || p != "mot de passe SMTP" {
		t.Fatalf("déchiffrement : %q %v", p, err)
	}
	if again, _ := b.Seal(s1); again != s1 {
		t.Fatal("une valeur déjà chiffrée ne doit pas être chiffrée deux fois")
	}
	if p, _ := b.Open("ancienne valeur en clair"); p != "ancienne valeur en clair" {
		t.Fatal("une valeur héritée en clair doit être lue telle quelle")
	}
	if v, _ := b.Seal(""); v != "" {
		t.Fatal("une valeur vide reste vide")
	}
}

func TestWrongOrMissingKey(t *testing.T) {
	b, _ := New(key())
	s, _ := b.Seal("secret")
	other, _ := New(base64.StdEncoding.EncodeToString([]byte("ffffffffffffffffffffffffffffffff")))
	if _, err := other.Open(s); err == nil {
		t.Fatal("une autre clé ne doit pas déchiffrer")
	}
	none, _ := New("")
	if _, err := none.Open(s); err != ErrNoKey {
		t.Fatalf("sans clé : ErrNoKey attendu, obtenu %v", err)
	}
	tampered := s[:len(s)-2] + "AA"
	if _, err := b.Open(tampered); err == nil {
		t.Fatal("une valeur altérée doit être refusée (authentification GCM)")
	}
	if _, err := New("trop-courte"); err == nil {
		t.Fatal("une clé de mauvaise taille doit être refusée")
	}
	if _, err := New(strings.Repeat("ab", 32)); err != nil {
		t.Fatalf("une clé hexadécimale de 32 octets doit être acceptée : %v", err)
	}
}
