package ua

import (
	"fmt"

	"github.com/amaneshi/crypto-dstu/internal/keystore"
)

// PKCS12Integrity selects the PFX password MAC independently of key encryption.
type PKCS12Integrity string

const (
	// PKCS12IntegritySHA256 uses the traditional BMP password-integrity profile.
	PKCS12IntegritySHA256 PKCS12Integrity = "pkcs12-sha256"
	// PKCS12IntegrityPBMAC1SHA256 uses RFC 9879 UTF-8 PBKDF2/HMAC-SHA256.
	PKCS12IntegrityPBMAC1SHA256 PKCS12Integrity = "pbmac1-sha256"
)

// PKCS12ExportOptions selects integrity. The zero value uses the existing BMP
// profile; explicit PBMAC1 accepts valid UTF-8 including supplementary characters.
// Both retain the 1..32 UTF-8-byte export limit and reject NUL.
type PKCS12ExportOptions struct{ Integrity PKCS12Integrity }

// ProtectPKCS12 exports one unencrypted PKCS#8 DER/PEM key with its matching
// certificate(s) and optional discovery certificates as a password-protected
// PFX. Embedded IIT agreement-key attributes are preserved; every contained key
// requires a matching certificate. Passwords follow ProtectKey's 1..32-byte
// limit, must be valid BMP UTF-8, and cannot contain NUL.
// Certificates are MAC-protected but unencrypted and are never trusted on import.
func ProtectPKCS12(rawKey []byte, certificates [][]byte, password string) ([]byte, error) {
	return ProtectPKCS12WithOptions(rawKey, certificates, password, PKCS12ExportOptions{})
}

// ProtectPKCS12WithOptions is ProtectPKCS12 with an explicit integrity profile.
func ProtectPKCS12WithOptions(rawKey []byte, certificates [][]byte, password string, options PKCS12ExportOptions) ([]byte, error) {
	certs := make([][]byte, len(certificates))
	for i, der := range certificates {
		certs[i] = keystore.MaybePEM(der)
	}
	return keystore.MarshalPKCS12WithOptions([][]byte{keystore.MaybePEM(rawKey)}, certs, password, keystore.PKCS12ExportOptions{Integrity: keystore.PKCS12Integrity(options.Integrity)})
}

// ExportPKCS12 exports all loaded private keys, matching certificates and
// discovery certificates. Key selection/roles do not filter the export. Missing
// or ambiguous certificate matches fail rather than discarding key material.
// Scalar values are preserved; raw PKCS#8 algorithm metadata is re-encoded using
// the library's supported named PB/ONB profile. No certificates become trust anchors.
func (b *Box) ExportPKCS12(password string) ([]byte, error) {
	return b.ExportPKCS12WithOptions(password, PKCS12ExportOptions{})
}

// ExportPKCS12WithOptions is ExportPKCS12 with an explicit integrity profile.
func (b *Box) ExportPKCS12WithOptions(password string, options PKCS12ExportOptions) ([]byte, error) {
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
	return keystore.MarshalPKCS12WithOptions(rawKeys, b.Certificates(), password, keystore.PKCS12ExportOptions{Integrity: keystore.PKCS12Integrity(options.Integrity)})
}
