package ua

import (
	"fmt"

	"github.com/amaneshi/crypto-dstu/internal/keystore"
)

// ProtectPKCS12 exports one unencrypted PKCS#8 DER/PEM key with its matching
// certificate(s) and optional discovery certificates as a password-protected
// PFX. Embedded IIT agreement-key attributes are preserved; every contained key
// requires a matching certificate. Passwords follow ProtectKey's 1..32-byte
// limit, must be valid BMP UTF-8, and cannot contain NUL.
// Certificates are MAC-protected but unencrypted and are never trusted on import.
func ProtectPKCS12(rawKey []byte, certificates [][]byte, password string) ([]byte, error) {
	certs := make([][]byte, len(certificates))
	for i, der := range certificates {
		certs[i] = keystore.MaybePEM(der)
	}
	return keystore.MarshalPKCS12([][]byte{keystore.MaybePEM(rawKey)}, certs, password)
}

// ExportPKCS12 exports all loaded private keys, matching certificates and
// discovery certificates. Key selection/roles do not filter the export. Missing
// or ambiguous certificate matches fail rather than discarding key material.
// Scalar values are preserved; raw PKCS#8 algorithm metadata is re-encoded using
// the library's supported PB profile. No certificates become trust anchors.
func (b *Box) ExportPKCS12(password string) ([]byte, error) {
	if b == nil || len(b.keys) == 0 {
		return nil, fmt.Errorf("ua: ExportPKCS12: no keys loaded")
	}
	var rawKeys [][]byte
	defer func() {
		for _, raw := range rawKeys {
			clear(raw)
		}
	}()
	for _, entry := range b.keys {
		raw, err := keystore.MarshalRawKey(entry.privateKey)
		if err != nil {
			return nil, fmt.Errorf("ua: ExportPKCS12: %w", err)
		}
		rawKeys = append(rawKeys, raw)
	}
	return keystore.MarshalPKCS12(rawKeys, b.Certificates(), password)
}
