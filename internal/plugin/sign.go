package plugin

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Formats texte des clés et signatures :
//
//	opencvec-pub-v1 <base64 clé publique>
//	opencvec-key-v1 <base64 clé privée>
//	opencvec-sig-v1 <id de clé> <base64 signature Ed25519 des octets exacts du fichier>
const (
	pubPrefix = "opencvec-pub-v1"
	keyPrefix = "opencvec-key-v1"
	sigPrefix = "opencvec-sig-v1"
)

// KeyID renvoie l'identifiant court d'une clé publique (8 octets de son SHA-256, en hexadécimal).
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8])
}

// GenerateKey crée une paire de clés au format texte.
func GenerateKey() (pubText, keyText string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return pubPrefix + " " + base64.StdEncoding.EncodeToString(pub),
		keyPrefix + " " + base64.StdEncoding.EncodeToString(priv), nil
}

// ParsePublicKey lit une clé publique au format texte.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	f := strings.Fields(s)
	if len(f) != 2 || f[0] != pubPrefix {
		return nil, errors.New("clé publique : format « opencvec-pub-v1 <base64> » attendu")
	}
	b, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("clé publique Ed25519 invalide")
	}
	return ed25519.PublicKey(b), nil
}

// ParsePrivateKey lit une clé privée au format texte.
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	f := strings.Fields(s)
	if len(f) != 2 || f[0] != keyPrefix {
		return nil, errors.New("clé privée : format « opencvec-key-v1 <base64> » attendu")
	}
	b, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(b) != ed25519.PrivateKeySize {
		return nil, errors.New("clé privée Ed25519 invalide")
	}
	return ed25519.PrivateKey(b), nil
}

// Sign signe les octets exacts d'un plugin.
func Sign(priv ed25519.PrivateKey, data []byte) string {
	pub := priv.Public().(ed25519.PublicKey)
	return fmt.Sprintf("%s %s %s\n", sigPrefix, KeyID(pub), base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data)))
}

// Publisher est un éditeur de confiance.
type Publisher struct {
	Name string
	Key  ed25519.PublicKey
}

// ErrUnsigned signale l'absence de signature.
var ErrUnsigned = errors.New("plugin non signé")

// Verify vérifie la signature d'un plugin et renvoie l'éditeur qui l'a signé.
func Verify(data []byte, sig string, trusted []Publisher) (Publisher, error) {
	sig = strings.TrimSpace(sig)
	if sig == "" {
		return Publisher{}, ErrUnsigned
	}
	f := strings.Fields(sig)
	if len(f) != 3 || f[0] != sigPrefix {
		return Publisher{}, errors.New("signature : format « opencvec-sig-v1 <id> <base64> » attendu")
	}
	raw, err := base64.StdEncoding.DecodeString(f[2])
	if err != nil || len(raw) != ed25519.SignatureSize {
		return Publisher{}, errors.New("signature illisible")
	}
	for _, p := range trusted {
		if KeyID(p.Key) != f[1] {
			continue
		}
		if ed25519.Verify(p.Key, data, raw) {
			return p, nil
		}
		return Publisher{}, fmt.Errorf("signature invalide pour l'éditeur %s : le fichier a été modifié", p.Name)
	}
	return Publisher{}, fmt.Errorf("clé de signature %s inconnue : ajoutez l'éditeur aux éditeurs de confiance", f[1])
}

// SHA256 renvoie l'empreinte hexadécimale d'un contenu.
func SHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
