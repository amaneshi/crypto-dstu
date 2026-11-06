package ua

import (
	"bytes"
	"errors"
)

// SigningCertificate returns a copy of the certificate matched to the selected
// signing key. A separate agreement key is allowed; multiple signing identities
// require explicit role selection.
func (b *Box) SigningCertificate() ([]byte, error) {
	entry, err := b.firstKey()
	if err != nil {
		return nil, err
	}
	if entry.signCert == nil {
		return nil, errors.New("ua: no signing certificate loaded")
	}
	return bytes.Clone(entry.signCert.Raw), nil
}

// SigningCertInfo returns the CertInfo of the certificate matched to the
// selected signing key, including its KeyID. It fails like SigningCertificate.
func (b *Box) SigningCertInfo() (*CertInfo, error) {
	entry, err := b.firstKey()
	if err != nil {
		return nil, err
	}
	if entry.signCert == nil {
		return nil, errors.New("ua: no signing certificate loaded")
	}
	return certInfoFromCert(entry.signCert), nil
}

// Certificates returns copies of loaded discovery certificates. They are not
// implicitly trusted roots, including certificates embedded in a key store.
func (b *Box) Certificates() [][]byte {
	result := make([][]byte, 0, len(b.certificates))
	for _, c := range b.certificates {
		result = append(result, bytes.Clone(c.Raw))
	}
	return result
}
