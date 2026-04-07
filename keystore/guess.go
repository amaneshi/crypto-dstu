package keystore

import (
	"errors"

	"crypto-dstu/dstu4145"
)

// Format identifies the detected key container format.
type Format string

const (
	FormatKey6    Format = "key6"
	FormatJKS     Format = "jks"
	FormatPKCS12  Format = "pkcs12"
	FormatRaw     Format = "raw"
	FormatPEM     Format = "pem"
	FormatUnknown Format = "unknown"
)

// ParseResult holds the output of auto-detected key parsing.
type ParseResult struct {
	Keys   []*dstu4145.PrivateKey
	Certs  [][]byte // DER-encoded certificates
	Format Format
}

// Parse auto-detects the key container format and returns parsed keys and certs.
// Parser order (matches cryptonite / jkurwa keycoder.js guess_parse chain):
//  1. Strip PEM / base64 armour
//  2. Try Key-6.dat (PBES2 EncryptedPrivateKeyInfo)
//  3. Try PKCS#12 / PFX
//  4. Try JKS (Java KeyStore)
//  5. Try raw unencrypted PrivateKeyInfo (PKCS#8 DER)
func Parse(data []byte, password string) (*ParseResult, error) {
	origData := data
	var format Format

	// Track whether the original input was PEM-wrapped
	wasPEM := IsPEM(data)
	data = MaybePEM(data)
	data = MaybeBase64(data)

	// 1. Try Key-6.dat (PBES2 EncryptedPrivateKeyInfo)
	if priv, err := ParseKey6(data, password); err == nil {
		f := FormatKey6
		if wasPEM {
			f = FormatPEM
		}
		return &ParseResult{Keys: []*dstu4145.PrivateKey{priv}, Format: f}, nil
	}

	// 2. Try PKCS#12 / PFX
	if pairs, err := ParsePKCS12(data, password); err == nil && len(pairs) > 0 {
		format = FormatPKCS12
		if wasPEM {
			format = FormatPEM
		}
		keys := make([]*dstu4145.PrivateKey, 0, len(pairs))
		certs := make([][]byte, 0)
		for _, p := range pairs {
			keys = append(keys, p.PrivateKey)
			if p.Cert != nil {
				certs = append(certs, p.Cert)
			}
			certs = append(certs, p.CertChain...)
		}
		return &ParseResult{Keys: keys, Certs: certs, Format: format}, nil
	}

	// 3. Try JKS
	if entries, err := ParseJKS(origData); err == nil && len(entries) > 0 {
		return &ParseResult{
			Keys:   nil, // JKS keys need separate decryption; return entries' raw data via Certs
			Certs:  collectJKSCerts(entries),
			Format: FormatJKS,
		}, nil
	}

	// 4. Try raw unencrypted PKCS#8 PrivateKeyInfo
	if priv, err := ParseRawKey(data); err == nil {
		f := FormatRaw
		if wasPEM {
			f = FormatPEM
		}
		return &ParseResult{Keys: []*dstu4145.PrivateKey{priv}, Format: f}, nil
	}

	return nil, errors.New("keystore: Parse: unknown or unsupported key format")
}

// ParseJKSWithPassword parses a JKS file and attempts to decrypt each key entry
// using ParseKey6 (the key data in PrivatBank JKS is a PKCS#8 encrypted blob).
func ParseJKSWithPassword(data []byte, password string) (*ParseResult, error) {
	entries, err := ParseJKS(data)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("keystore: JKS: no entries found")
	}

	var keys []*dstu4145.PrivateKey
	var certs [][]byte
	var priv *dstu4145.PrivateKey

	for _, entry := range entries {
		// Each entry's KeyDER is a PKCS#8 encrypted blob (same as Key-6.dat)
		if priv, err = ParseKey6(entry.KeyDER, password); err == nil {
			keys = append(keys, priv)
		}
		certs = append(certs, entry.CertChain...)
	}

	if len(keys) == 0 {
		return nil, errors.New("keystore: JKS: no keys could be decrypted (wrong password?)")
	}

	return &ParseResult{Keys: keys, Certs: certs, Format: FormatJKS}, nil
}

func collectJKSCerts(entries []JKSEntry) [][]byte {
	var certs [][]byte
	for _, e := range entries {
		certs = append(certs, e.CertChain...)
	}
	return certs
}
