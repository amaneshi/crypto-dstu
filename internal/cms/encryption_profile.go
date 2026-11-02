package cms

import (
	"encoding/asn1"
	"errors"

	"crypto-dstu/internal/cert"
	"crypto-dstu/pkg/dstu15946"
	"crypto-dstu/pkg/dstu4145"
	"crypto-dstu/pkg/gost28147"
	"crypto-dstu/pkg/gost34311"
	"crypto-dstu/pkg/kalyna"
	"crypto-dstu/pkg/kupyna"
)

// EncryptOptions selects a complete supported envelope profile. A nil Algorithm
// selects GOST CFB. OriginatorCertificate selects a static certificate reference.
type EncryptOptions struct {
	Algorithm             asn1.ObjectIdentifier
	OriginatorCertificate *cert.Certificate
}

// EncryptWithOptions encrypts using explicit cipher, agreement and wrapping
// algorithms. Discovery certificates do not establish sender trust.
func EncryptWithOptions(
	content []byte,
	recipients []*cert.Certificate,
	key *dstu4145.PrivateKey,
	options EncryptOptions,
) ([]byte, error) {
	if key == nil || key.Curve == nil || key.D == nil {
		return nil, errors.New("cms: sender key is required")
	}
	if options.OriginatorCertificate != nil {
		if err := cert.VerifyCertPKMatch(options.OriginatorCertificate, key); err != nil {
			return nil, err
		}
		if err := cert.CheckEncryptionUsage(options.OriginatorCertificate); err != nil {
			return nil, err
		}
	}
	return encrypt(content, recipients, key, options.OriginatorCertificate, options.Algorithm)
}

type envelopeProfile struct {
	content, agreement, wrap asn1.ObjectIdentifier
	ivSize                   int
	dke                      []byte
}

func profileForCipher(algorithm asn1.ObjectIdentifier) (envelopeProfile, error) {
	switch {
	case algorithm.Equal(OIDGost28147CFB):
		return envelopeProfile{algorithm, OIDDSTU4145DH, OIDGost28147Wrap, 8, gost28147.SboxDSTU.Packed()}, nil
	case algorithm.Equal(OIDKalyna256CFB), algorithm.Equal(OIDKalyna256OFB):
		return envelopeProfile{algorithm, OIDKupynaDH, OIDKalynaWrap, 32, nil}, nil
	default:
		return envelopeProfile{}, errors.New("cms: unsupported content encryption profile")
	}
}

func envelopeKEK(
	key *dstu4145.PrivateKey,
	peer *dstu4145.PublicKey,
	ukm []byte,
	algorithm asn1.ObjectIdentifier,
) ([]byte, error) {
	switch {
	case algorithm.Equal(OIDDSTU4145DH):
		return dstu15946.KeyAgreement(key, peer, ukm, gost34311.New)
	case algorithm.Equal(OIDKupynaDH):
		zz, err := dstu15946.SharedSecret(key, peer)
		if err != nil {
			return nil, err
		}
		defer clear(zz)
		return dstu15946.DeriveKeyForWrap(zz, ukm, kupyna.New256, OIDKalynaWrap)
	default:
		return nil, errors.New("cms: unsupported key agreement algorithm")
	}
}

func cryptEnvelopeContent(profile envelopeProfile, key, iv, content []byte, decrypt bool) ([]byte, error) {
	switch {
	case profile.content.Equal(OIDGost28147CFB):
		if decrypt {
			return gost28147.DecryptCFB(key, iv, content)
		}
		return gost28147.EncryptCFB(key, iv, content)
	case profile.content.Equal(OIDKalyna256CFB):
		if decrypt {
			return kalyna.DecryptCFB(key, iv, content)
		}
		return kalyna.EncryptCFB(key, iv, content)
	case profile.content.Equal(OIDKalyna256OFB):
		return kalyna.CryptOFB(key, iv, content)
	default:
		return nil, errors.New("cms: unsupported content cipher")
	}
}
