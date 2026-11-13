// Package auth fournit les primitives d'authentification : jetons aléatoires,
// empreintes de jetons et hachage des mots de passe administrateur.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"golang.org/x/crypto/bcrypt"
)

// NewToken renvoie un jeton aléatoire de 256 bits encodé en base64 URL.
func NewToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("source d'aléa indisponible : " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashToken renvoie l'empreinte SHA-256 d'un jeton. Seule l'empreinte est stockée :
// une fuite de la base ne donne pas accès aux sessions ni aux comptes.
func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// HashPassword hache un mot de passe administrateur avec bcrypt.
func HashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	return string(h), err
}

// CheckPassword compare un mot de passe à son empreinte bcrypt.
func CheckPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}
