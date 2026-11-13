package auth

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// Vecteurs de la RFC 6238 (annexe B, SHA-1, secret ASCII « 12345678901234567890 »),
// tronqués aux 6 derniers chiffres comme le font les applications d'authentification.
func TestTOTPRFC6238(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	cases := []struct {
		unix int64
		want string // 8 chiffres dans la RFC
	}{{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}}
	for _, c := range cases {
		got, err := TOTPCode(secret, uint64(c.unix/TOTPPeriod))
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want[2:] {
			t.Errorf("t=%d : %s, attendu %s", c.unix, got, c.want[2:])
		}
	}
}

func TestVerifyTOTPWindowAndReplay(t *testing.T) {
	secret := NewTOTPSecret()
	now := time.Unix(1_800_000_000, 0)
	cur := now.Unix() / TOTPPeriod
	code, _ := TOTPCode(secret, uint64(cur))
	c, ok := VerifyTOTP(secret, code, now, 0)
	if !ok || c != cur {
		t.Fatal("le code courant doit être accepté")
	}
	if _, ok := VerifyTOTP(secret, code, now, c); ok {
		t.Fatal("un code déjà utilisé doit être refusé (rejeu)")
	}
	prev, _ := TOTPCode(secret, uint64(cur-1))
	if _, ok := VerifyTOTP(secret, prev, now, 0); !ok {
		t.Fatal("le code du pas précédent doit être toléré (décalage d'horloge)")
	}
	old, _ := TOTPCode(secret, uint64(cur-3))
	if _, ok := VerifyTOTP(secret, old, now, 0); ok {
		t.Fatal("un code trop ancien doit être refusé")
	}
	if _, ok := VerifyTOTP(secret, "12345", now, 0); ok {
		t.Fatal("un code de mauvaise longueur doit être refusé")
	}
	spaced := code[:3] + " " + code[3:]
	if _, ok := VerifyTOTP(secret, spaced, now.Add(30*time.Second), 0); !ok {
		t.Fatal("les espaces saisis doivent être ignorés")
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes := NewRecoveryCodes(10)
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 14 || strings.Count(c, "-") != 2 || seen[c] {
			t.Fatalf("code de secours invalide ou en double : %q", c)
		}
		seen[c] = true
		if NormalizeRecoveryCode(strings.ToUpper(strings.ReplaceAll(c, "-", " "))) != c {
			t.Fatalf("normalisation incorrecte pour %q", c)
		}
	}
}

func TestTOTPURI(t *testing.T) {
	u := TOTPURI("OpenCVEC", "admin@exemple.fr", "ABC")
	if !strings.HasPrefix(u, "otpauth://totp/OpenCVEC:admin@exemple.fr?") || !strings.Contains(u, "secret=ABC") || !strings.Contains(u, "issuer=OpenCVEC") {
		t.Fatalf("URI inattendue : %s", u)
	}
}
