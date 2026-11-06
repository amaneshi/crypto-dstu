package ua

import (
	"bytes"
	"errors"

	"github.com/amaneshi/crypto-dstu/internal/cert"
)

// Key is one opened signing identity: a decrypted private key and its matched
// signing certificate. Open it once with OpenKey and sign with it through a
// Signer as often as needed. A Key is immutable and safe for concurrent use.
type Key struct {
	entry *keyEntry
	// discovery holds every certificate found in the container or supplied to
	// OpenKey. It helps build TSA paths; it is never a trust anchor.
	discovery []*cert.Certificate
}

// OpenKey decrypts a key container (Key-6.dat, JKS, PKCS#12, PKCS#8 or PEM,
// auto-detected) and returns its signing identity. certificates are optional
// extra DER/PEM certificates for containers that do not embed their own. It
// fails when the container holds no signing identity, or more than one; use
// OpenKeyByRole for multi-identity containers.
func OpenKey(data []byte, password string, certificates ...[]byte) (*Key, error) {
	return openKey(data, password, "", certificates)
}

// OpenKeyByRole is OpenKey for containers holding several signing identities
// (for example a director and a stamp key in one JKS). role is one of
// "personal", "fop", "director", "stamp" or "other" and must match exactly one key.
func OpenKeyByRole(data []byte, password, role string, certificates ...[]byte) (*Key, error) {
	if role == "" {
		return nil, errors.New("ua: OpenKeyByRole: role is required")
	}
	return openKey(data, password, role, certificates)
}

func openKey(data []byte, password, role string, certificates [][]byte) (*Key, error) {
	box := NewBox()
	if err := box.LoadKey(data, password); err != nil {
		return nil, err
	}
	for _, der := range certificates {
		if err := box.AddCert(der); err != nil {
			return nil, err
		}
	}
	if role != "" {
		if err := box.SelectKeyByRole(role); err != nil {
			return nil, err
		}
	}
	entry, err := box.firstKey()
	if err != nil {
		return nil, err
	}
	if entry.signCert == nil {
		return nil, errors.New("ua: OpenKey: no signing certificate matches the key")
	}
	return &Key{entry: entry, discovery: box.certificates}, nil
}

// Info returns the signing certificate's details, including KeyID.
func (k *Key) Info() *CertInfo {
	return certInfoFromCert(k.entry.signCert)
}

// Certificate returns a copy of the signing certificate (DER).
func (k *Key) Certificate() []byte {
	return bytes.Clone(k.entry.signCert.Raw)
}
