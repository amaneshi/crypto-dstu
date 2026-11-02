package ua

import (
	"crypto/rand"
	"errors"

	"github.com/amaneshi/crypto-dstu/internal/keystore"
)

// ProtectKey encrypts a single unencrypted PKCS#8 DER or PEM DSTU key into a
// Key-6 EncryptedPrivateKeyInfo using PBKDF2 with Kupyna MAC-256 (10,000
// iterations) and Kalyna-256 CBC. Every call generates a new 32-byte salt and IV.
// The password must contain 1 to 32 UTF-8 bytes. Certificates are not included.
// The password bytes are zero-padded, so trailing NUL bytes are rejected.
func ProtectKey(rawKey []byte, password string) ([]byte, error) {
	if len(password) == 0 || len(password) > 32 || password[len(password)-1] == 0 {
		return nil, errors.New("ua: ProtectKey: password must contain 1 to 32 bytes and must not end in NUL")
	}
	raw := keystore.MaybePEM(rawKey)
	if _, err := keystore.ParseRawKey(raw); err != nil {
		return nil, errors.New("ua: ProtectKey: expected a single unencrypted PKCS#8 DSTU key: " + err.Error())
	}
	salt, iv := make([]byte, 32), make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	return keystore.MarshalKey6Kalyna(raw, password, salt, 10000, iv)
}
