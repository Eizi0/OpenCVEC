// Package canary génère et analyse les jetons canaris.
//
// Un jeton vaut base32(nonce ‖ HMAC-SHA256(clé, asset ‖ check ‖ nonce)[:mac]) en minuscules,
// soit 20 caractères utilisables comme étiquette DNS. Il est enregistré en base avec son asset
// et son check ; à la réception d'un callback, la signature est recalculée avec les identifiants
// enregistrés : un jeton fabriqué ou une ligne altérée est rejeté.
package canary

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"strings"
)

const (
	nonceLen = 6
	macLen   = 6
	// TokenLen est la longueur d'un jeton encodé.
	TokenLen = 20
)

var enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// Signer fabrique et vérifie les jetons avec une clé secrète.
type Signer struct{ key []byte }

// NewSigner construit un Signer ; la clé doit faire au moins 32 octets.
func NewSigner(key []byte) (*Signer, error) {
	if len(key) < 32 {
		return nil, errors.New("clé canari trop courte (32 octets minimum)")
	}
	return &Signer{key: append([]byte(nil), key...)}, nil
}

func (s *Signer) mac(assetID, checkID int64, nonce []byte) []byte {
	m := hmac.New(sha256.New, s.key)
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(assetID))
	binary.BigEndian.PutUint64(b[8:], uint64(checkID))
	m.Write(b[:])
	m.Write(nonce)
	return m.Sum(nil)[:macLen]
}

// New renvoie un jeton neuf pour un couple asset × check.
func (s *Signer) New(assetID, checkID int64) string {
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		panic("source d'aléa indisponible : " + err.Error())
	}
	raw := append(nonce, s.mac(assetID, checkID, nonce)...)
	return strings.ToLower(enc.EncodeToString(raw))
}

// Verify indique si le jeton a bien été signé pour cet asset et ce check.
func (s *Signer) Verify(token string, assetID, checkID int64) bool {
	raw, err := enc.DecodeString(strings.ToUpper(token))
	if err != nil || len(raw) != nonceLen+macLen {
		return false
	}
	return hmac.Equal(raw[nonceLen:], s.mac(assetID, checkID, raw[:nonceLen]))
}

// Parsed décrit un nom reçu par le récepteur.
type Parsed struct {
	Token string // jeton (vide s'il n'a pas la bonne forme)
	Point string // préfixe facultatif désignant le point d'injection (p1, p2…)
}

// Parse extrait le jeton d'un nom de la zone : [point.]jeton.zone. La casse est ignorée
// (certains résolveurs la randomisent, « 0x20 »).
func Parse(name, zone string) (Parsed, bool) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	if name == zone {
		return Parsed{}, true
	}
	if !strings.HasSuffix(name, "."+zone) {
		return Parsed{}, false
	}
	labels := strings.Split(strings.TrimSuffix(name, "."+zone), ".")
	tok := labels[len(labels)-1]
	if !LooksLikeToken(tok) {
		return Parsed{}, true
	}
	p := Parsed{Token: tok}
	if len(labels) >= 2 {
		p.Point = labels[len(labels)-2]
	}
	return p, true
}

// LooksLikeToken vérifie la forme d'un jeton (longueur et alphabet base32).
func LooksLikeToken(s string) bool {
	if len(s) != TokenLen {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}

// Host renvoie le nom complet d'un point d'injection : point.jeton.zone.
func Host(point, token, zone string) string {
	if point == "" {
		return token + "." + zone
	}
	return point + "." + token + "." + zone
}
