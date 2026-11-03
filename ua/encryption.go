package ua

import (
	"encoding/asn1"
	"fmt"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/keystore"
)

// EncryptionAlgorithm identifies a supported CMS content cipher.
type EncryptionAlgorithm string

const (
	EncryptionGOST28147CFB EncryptionAlgorithm = "gost28147-cfb"
	EncryptionKalyna256CFB EncryptionAlgorithm = "kalyna256-cfb"
	EncryptionKalyna256OFB EncryptionAlgorithm = "kalyna256-ofb"
)

// KeyAgreementAlgorithm selects the CMS agreement scheme independently of its cipher.
type KeyAgreementAlgorithm string

const (
	AgreementCofactorDH KeyAgreementAlgorithm = "cofactor-dh"
	AgreementStandardDH KeyAgreementAlgorithm = "standard-dh"
)

// EncryptionOptions selects the content cipher and its associated KDF/wrap.
// The zero value preserves the GOST CFB default.
type EncryptionOptions struct {
	Algorithm EncryptionAlgorithm
	// Agreement defaults to cofactor DH. Standard DH is explicit and requires
	// a Kalyna cipher and validation of the peer's prime-order subgroup.
	Agreement KeyAgreementAlgorithm
	// StaticOriginator references and embeds the matched agreement certificate.
	// This supplies sender certificate discovery, not trust or content authentication.
	StaticOriginator bool
}

func (options EncryptionOptions) algorithmOID() (asn1.ObjectIdentifier, error) {
	agreement, err := options.agreementOID()
	if err != nil {
		return nil, err
	}
	var algorithm asn1.ObjectIdentifier
	switch options.Algorithm {
	case "", EncryptionGOST28147CFB:
		algorithm = cms.OIDGost28147CFB
	case EncryptionKalyna256CFB:
		algorithm = cms.OIDKalyna256CFB
	case EncryptionKalyna256OFB:
		algorithm = cms.OIDKalyna256OFB
	default:
		return nil, fmt.Errorf("ua: unsupported encryption algorithm %q", options.Algorithm)
	}
	if len(agreement) != 0 && algorithm.Equal(cms.OIDGost28147CFB) {
		return nil, fmt.Errorf("ua: standard DH requires a Kalyna encryption profile")
	}
	return algorithm, nil
}

func (options EncryptionOptions) agreementOID() (asn1.ObjectIdentifier, error) {
	switch options.Agreement {
	case "", AgreementCofactorDH:
		return nil, nil
	case AgreementStandardDH:
		return cms.OIDKupynaStandardDH, nil
	default:
		return nil, fmt.Errorf("ua: unsupported key agreement %q", options.Agreement)
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
