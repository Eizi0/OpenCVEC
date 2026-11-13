// Package secrets chiffre au repos les secrets stockés en base (secrets TOTP, clé des canaris)
// avec AES-256-GCM et une clé fournie par l'environnement (OPENCVEC_SECRET_KEY).
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Prefix identifie une valeur chiffrée. Une valeur sans préfixe est un héritage en clair,
// lu tel quel puis chiffré au démarrage suivant.
const Prefix = "enc:v1:"

// ErrNoKey est renvoyée quand une valeur chiffrée est lue sans clé configurée.
var ErrNoKey = errors.New("OPENCVEC_SECRET_KEY absente : impossible de déchiffrer les secrets enregistrés")

// Box chiffre et déchiffre. Une Box sans clé laisse les valeurs en clair (mode dégradé signalé au démarrage).
type Box struct {
	aead cipher.AEAD
}

// New construit une Box à partir d'une clé de 32 octets encodée en base64 ou en hexadécimal.
// Une clé vide donne une Box sans chiffrement.
func New(key string) (*Box, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return &Box{}, nil
	}
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) != 32 {
		raw, err = hex.DecodeString(key)
	}
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("OPENCVEC_SECRET_KEY doit faire 32 octets, en base64 (openssl rand -base64 32) ou en hexadécimal")
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Enabled indique si une clé est configurée.
func (b *Box) Enabled() bool { return b != nil && b.aead != nil }

// Seal chiffre une valeur. Vide reste vide ; sans clé, la valeur est renvoyée telle quelle.
func (b *Box) Seal(plain string) (string, error) {
	if plain == "" || !b.Enabled() || IsSealed(plain) {
		return plain, nil
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := b.aead.Seal(nonce, nonce, []byte(plain), nil)
	return Prefix + base64.RawStdEncoding.EncodeToString(ct), nil
}

// Open déchiffre une valeur. Une valeur en clair (héritée) est renvoyée telle quelle.
func (b *Box) Open(v string) (string, error) {
	if !IsSealed(v) {
		return v, nil
	}
	if !b.Enabled() {
		return "", ErrNoKey
	}
	ct, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(v, Prefix))
	if err != nil || len(ct) < b.aead.NonceSize() {
		return "", errors.New("secret chiffré illisible")
	}
	n := b.aead.NonceSize()
	pt, err := b.aead.Open(nil, ct[:n], ct[n:], nil)
	if err != nil {
		return "", errors.New("secret indéchiffrable : la clé OPENCVEC_SECRET_KEY a-t-elle changé ?")
	}
	return string(pt), nil
}

// IsSealed indique si la valeur est chiffrée.
func IsSealed(v string) bool { return strings.HasPrefix(v, Prefix) }
