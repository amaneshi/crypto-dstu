// Package keystore implements parsers for all private key container formats
// used in Ukrainian PKI: Key-6.dat (PBES2), JKS, PKCS#12, raw DER/PEM.
// Reference: cryptonite src/storage/c — pkcs5.c, pkcs8.c, pkcs12.c
package keystore

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
)

// IsPEM reports whether data begins with a PEM header.
func IsPEM(data []byte) bool {
	for i := range data {
		if data[i] == '-' {
			return len(data[i:]) >= 5 && string(data[i:i+5]) == "-----"
		}
		// skip leading whitespace/BOM
		if data[i] != ' ' && data[i] != '\t' && data[i] != '\r' && data[i] != '\n' && data[i] != 0xEF {
			return false
		}
	}
	return false
}

// DecodePEM strips PEM armour and returns raw DER bytes plus the type label
// (e.g. "PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "CERTIFICATE").
func DecodePEM(data []byte) ([]byte, string, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, "", errors.New("keystore: no PEM block found")
	}
	return block.Bytes, block.Type, nil
}

// EncodePEM wraps DER bytes in PEM armour with the given type label.
func EncodePEM(der []byte, pemType string) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der})
}

// MaybePEM decodes PEM if data looks like PEM; otherwise returns data unchanged.
func MaybePEM(data []byte) []byte {
	if !IsPEM(data) {
		return data
	}
	der, _, err := DecodePEM(data)
	if err != nil {
		return data
	}
	return der
}

// IsBase64DER reports whether data is base64-encoded DER (no PEM header).
// Some Ukrainian CA tools export keys as raw base64 without PEM armour.
func IsBase64DER(data []byte) bool {
	if IsPEM(data) {
		return false
	}
	// Attempt base64 decode; if it succeeds and the result starts with 0x30
	// (ASN.1 SEQUENCE), treat it as base64 DER.
	buf := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(buf, trimWhitespace(data))
	if err != nil {
		return false
	}
	return n > 0 && buf[0] == 0x30
}

// MaybeBase64 decodes base64 if data looks like base64 DER; otherwise returns as-is.
func MaybeBase64(data []byte) []byte {
	if !IsBase64DER(data) {
		return data
	}
	buf := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(buf, trimWhitespace(data))
	if err != nil {
		return data
	}
	return buf[:n]
}

func trimWhitespace(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			out = append(out, c)
		}
	}
	return out
}
