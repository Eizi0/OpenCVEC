package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Paramètres TOTP (RFC 6238) compatibles avec toutes les applications d'authentification
// courantes : HMAC-SHA1, pas de 30 secondes, 6 chiffres.
const (
	TOTPPeriod = 30
	TOTPDigits = 6
	// TOTPSkew accepte le pas précédent et le suivant (décalage d'horloge du téléphone).
	TOTPSkew = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret génère un secret de 160 bits encodé en base32.
func NewTOTPSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b32.EncodeToString(b)
}

// TOTPCode calcule le code pour un compteur donné.
func TOTPCode(secret string, counter uint64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("secret TOTP invalide : %w", err)
	}
	return hotp(key, counter, TOTPDigits), nil
}

func hotp(key []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod)
}

// VerifyTOTP vérifie un code et renvoie le compteur correspondant. Le code est refusé
// si son compteur n'est pas strictement supérieur à lastCounter : un code déjà utilisé
// (intercepté, ou rejoué) ne peut pas servir une deuxième fois.
func VerifyTOTP(secret, code string, now time.Time, lastCounter int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != TOTPDigits {
		return 0, false
	}
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return 0, false
	}
	cur := now.Unix() / TOTPPeriod
	for d := -TOTPSkew; d <= TOTPSkew; d++ {
		c := cur + int64(d)
		if c <= lastCounter || c < 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(hotp(key, uint64(c), TOTPDigits)), []byte(code)) == 1 {
			return c, true
		}
	}
	return 0, false
}

// TOTPURI construit l'URI otpauth:// à encoder dans le QR code.
func TOTPURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// NewRecoveryCodes génère n codes de secours lisibles (xxxx-xxxx-xxxx, alphabet sans ambiguïté).
func NewRecoveryCodes(n int) []string {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	out := make([]string, n)
	for i := range out {
		b := make([]byte, 12)
		if _, err := rand.Read(b); err != nil {
			panic(err)
		}
		var sb strings.Builder
		for j, c := range b {
			if j > 0 && j%4 == 0 {
				sb.WriteByte('-')
			}
			sb.WriteByte(alphabet[int(c)%len(alphabet)])
		}
		out[i] = sb.String()
	}
	return out
}

// NormalizeRecoveryCode rend la saisie tolérante (casse, espaces, tirets).
func NormalizeRecoveryCode(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer(" ", "", "-", "").Replace(s)
	if len(s) != 12 {
		return s
	}
	return s[0:4] + "-" + s[4:8] + "-" + s[8:12]
}
