// Package secretbox encrypts small team secrets (Slack webhook URL, Jira API
// token) before they are stored, with AES-256-GCM and a key from the
// DEPGUARD_SECRET_KEY environment variable (64 hex characters).
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
)

// ErrNoKey means DEPGUARD_SECRET_KEY is missing or not 32 bytes of hex.
var ErrNoKey = errors.New("DEPGUARD_SECRET_KEY is not configured")

func aead() (cipher.AEAD, error) {
	key, err := hex.DecodeString(os.Getenv("DEPGUARD_SECRET_KEY"))
	if err != nil || len(key) != 32 {
		return nil, ErrNoKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts plaintext; aad binds the ciphertext to its owner (tenant/name).
func Seal(plaintext, aad string) ([]byte, error) {
	g, err := aead()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, []byte(plaintext), []byte(aad)), nil
}

// Open decrypts a value from Seal with the same aad.
func Open(box []byte, aad string) (string, error) {
	g, err := aead()
	if err != nil {
		return "", err
	}
	if len(box) < g.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	out, err := g.Open(nil, box[:g.NonceSize()], box[g.NonceSize():], []byte(aad))
	return string(out), err
}
