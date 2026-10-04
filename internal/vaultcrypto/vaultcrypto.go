// Package vaultcrypto is the end-to-end encryption of the project vault. It is
// the Go twin of web/lib/vault-crypto.ts (browser, WebCrypto): both must stay
// byte-compatible (testdata/vectors.json is produced by the browser code).
//
//	member key pair : ECDH P-256. The PKCS#8 private key is sealed with the
//	                  member's passphrase: PBKDF2-SHA256 → AES-256-GCM.
//	vault key       : 32 random bytes per project, wrapped for each member:
//	                  ECDH(ephemeral, member) → HKDF-SHA256 → AES-256-GCM.
//	item            : AES-256-GCM(vault key), bound to project and item name.
package vaultcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// Iterations is the PBKDF2 work factor for passphrases (OWASP 2023 for SHA-256).
const Iterations = 600_000

var b64 = base64.StdEncoding

// WrappedPrivate is a member's private key sealed with their passphrase.
type WrappedPrivate struct {
	Salt       string `json:"salt"`
	Iterations int    `json:"iterations"`
	IV         string `json:"iv"`
	Ciphertext string `json:"ciphertext"`
}

// WrappedKey is a project vault key sealed for one member.
type WrappedKey struct {
	EphemeralPublic string `json:"ephemeral_public"`
	IV              string `json:"iv"`
	Ciphertext      string `json:"ciphertext"`
}

// ErrWrongPassphrase is returned when the passphrase does not open the key.
var ErrWrongPassphrase = errors.New("wrong vault passphrase")

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func seal(key, plaintext, aad []byte) (iv, ct string, err error) {
	g, err := gcm(key)
	if err != nil {
		return "", "", err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", "", err
	}
	return b64.EncodeToString(nonce), b64.EncodeToString(g.Seal(nil, nonce, plaintext, aad)), nil
}

func open(key []byte, iv, ct string, aad []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce, err1 := b64.DecodeString(iv)
	data, err2 := b64.DecodeString(ct)
	if err := errors.Join(err1, err2); err != nil {
		return nil, err
	}
	if len(nonce) != g.NonceSize() {
		return nil, errors.New("bad nonce")
	}
	return g.Open(nil, nonce, data, aad)
}

const (
	memberAAD = "depguard-vault-member-v1"
	keyInfo   = "depguard-vault-key-v1"
	itemAAD   = "depguard-vault-item-v1"
)

func passKey(passphrase string, salt []byte, iter int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, passphrase, salt, iter, 32)
}

// NewMember creates a key pair and seals the private key with passphrase.
func NewMember(passphrase string) (*ecdh.PrivateKey, string, WrappedPrivate, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", WrappedPrivate{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, "", WrappedPrivate{}, err
	}
	salt := make([]byte, 16)
	rand.Read(salt)
	k, err := passKey(passphrase, salt, Iterations)
	if err != nil {
		return nil, "", WrappedPrivate{}, err
	}
	iv, ct, err := seal(k, der, []byte(memberAAD))
	return priv, b64.EncodeToString(priv.PublicKey().Bytes()), WrappedPrivate{b64.EncodeToString(salt), Iterations, iv, ct}, err
}

// UnwrapPrivate opens a member's private key with their passphrase.
func UnwrapPrivate(w WrappedPrivate, passphrase string) (*ecdh.PrivateKey, error) {
	salt, err := b64.DecodeString(w.Salt)
	if err != nil || w.Iterations < 100_000 {
		return nil, errors.New("bad wrapped key")
	}
	k, err := passKey(passphrase, salt, w.Iterations)
	if err != nil {
		return nil, err
	}
	der, err := open(k, w.IV, w.Ciphertext, []byte(memberAAD))
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return ParsePKCS8(der)
}

// ParsePKCS8 reads a P-256 private key (WebCrypto exports ECDH keys as EC PKCS#8).
func ParsePKCS8(der []byte) (*ecdh.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	switch k := k.(type) {
	case *ecdsa.PrivateKey:
		return k.ECDH()
	case *ecdh.PrivateKey:
		return k, nil
	}
	return nil, fmt.Errorf("unexpected key type %T", k)
}

func kek(shared, ephPub []byte, projectID, userID string) ([]byte, error) {
	return hkdf.Key(sha256.New, shared, ephPub, keyInfo+"|"+projectID+"|"+userID, 32)
}

// WrapKey seals a vault key for a member's public key (base64 raw point).
func WrapKey(vaultKey []byte, memberPublic, projectID, userID string) (WrappedKey, error) {
	raw, err := b64.DecodeString(memberPublic)
	if err != nil {
		return WrappedKey{}, err
	}
	pub, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		return WrappedKey{}, err
	}
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return WrappedKey{}, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return WrappedKey{}, err
	}
	k, err := kek(shared, eph.PublicKey().Bytes(), projectID, userID)
	if err != nil {
		return WrappedKey{}, err
	}
	iv, ct, err := seal(k, vaultKey, nil)
	return WrappedKey{b64.EncodeToString(eph.PublicKey().Bytes()), iv, ct}, err
}

// UnwrapKey opens the vault key wrapped for this member.
func UnwrapKey(priv *ecdh.PrivateKey, w WrappedKey, projectID, userID string) ([]byte, error) {
	raw, err := b64.DecodeString(w.EphemeralPublic)
	if err != nil {
		return nil, err
	}
	eph, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(eph)
	if err != nil {
		return nil, err
	}
	k, err := kek(shared, raw, projectID, userID)
	if err != nil {
		return nil, err
	}
	key, err := open(k, w.IV, w.Ciphertext, nil)
	if err != nil || len(key) != 32 {
		return nil, errors.New("this vault key was not wrapped for you")
	}
	return key, nil
}

func itemAD(projectID, name string) []byte { return []byte(itemAAD + "|" + projectID + "|" + name) }

// EncryptItem seals a vault item (bound to its project and name).
func EncryptItem(vaultKey, plaintext []byte, projectID, name string) (iv, ct string, err error) {
	return seal(vaultKey, plaintext, itemAD(projectID, name))
}

// DecryptItem opens a vault item.
func DecryptItem(vaultKey []byte, iv, ct, projectID, name string) ([]byte, error) {
	b, err := open(vaultKey, iv, ct, itemAD(projectID, name))
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt %s: wrong key or tampered data", name)
	}
	return b, nil
}

// Fingerprint is the SHA-256 (hex) of a secret value, used to match leaked keys.
func Fingerprint(value string) string {
	s := sha256.Sum256([]byte(value))
	return hex.EncodeToString(s[:])
}
