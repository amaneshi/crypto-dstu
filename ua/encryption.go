package ua

import (
	"encoding/asn1"
	"fmt"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/keystore"
)

// EncryptionAlgorithm identifies a complete supported CMS encryption profile.
type EncryptionAlgorithm string

const (
	EncryptionGOST28147CFB EncryptionAlgorithm = "gost28147-cfb"
	EncryptionKalyna256CFB EncryptionAlgorithm = "kalyna256-cfb"
	EncryptionKalyna256OFB EncryptionAlgorithm = "kalyna256-ofb"
)

// EncryptionOptions selects the content cipher and its associated KDF/wrap.
// The zero value preserves the GOST CFB default.
type EncryptionOptions struct {
	Algorithm EncryptionAlgorithm
	// StaticOriginator references and embeds the matched agreement certificate.
	// This supplies sender certificate discovery, not trust or content authentication.
	StaticOriginator bool
}

func (options EncryptionOptions) algorithmOID() (asn1.ObjectIdentifier, error) {
	switch options.Algorithm {
	case "", EncryptionGOST28147CFB:
		return cms.OIDGost28147CFB, nil
	case EncryptionKalyna256CFB:
		return cms.OIDKalyna256CFB, nil
	case EncryptionKalyna256OFB:
		return cms.OIDKalyna256OFB, nil
	default:
		return nil, fmt.Errorf("ua: unsupported encryption algorithm %q", options.Algorithm)
	}
}

// EncryptDocumentWithOptions encrypts using an explicitly selected CMS profile.
func (b *Box) EncryptDocumentWithOptions(content, recipientDER []byte, options EncryptionOptions) ([]byte, error) {
	if _, err := options.algorithmOID(); err != nil {
		return nil, err
	}
	recipient, err := cert.ParseCertificate(keystore.MaybePEM(recipientDER))
	if err != nil {
		return nil, err
	}
	return b.encryptDocumentWithOptions(content, recipient, options)
}
