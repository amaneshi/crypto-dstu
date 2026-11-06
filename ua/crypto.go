package ua

import (
	"bytes"
	"context"
	"errors"
	"slices"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/keystore"
	"github.com/amaneshi/crypto-dstu/internal/transport"
)

const defaultFilename = "document.xml"

// certCryptLabel names the transport section carrying the sender's agreement
// certificate ahead of its UA1_CRYPT envelope.
const certCryptLabel = "CERTCRYPT"

// EncryptDocument encrypts content for a recipient using ECDH+GOST28147.
// recipientDER is the recipient's DER- or PEM-encoded certificate.
// Returns raw CMS EnvelopedData DER bytes.
func (b *Box) EncryptDocument(content []byte, recipientDER []byte) ([]byte, error) {
	return b.EncryptDocumentWithOptions(content, recipientDER, EncryptionOptions{})
}

func (b *Box) encryptDocument(content []byte, rc *cert.Certificate) ([]byte, error) {
	return b.encryptDocumentWithOptions(content, rc, EncryptionOptions{})
}

func (b *Box) encryptDocumentWithOptions(content []byte, rc *cert.Certificate, options EncryptionOptions) ([]byte, error) {
	der, _, err := b.encryptWithAgreementKey(content, rc, options, true)
	return der, err
}

// encryptWithAgreementKey encrypts content and also returns the sender's
// agreement certificate used for the key agreement. embedOriginator controls
// whether a static originator certificate is also placed in OriginatorInfo;
// tax transport carries it in CERTCRYPT instead, as DPS's own envelopes do.
func (b *Box) encryptWithAgreementKey(content []byte, rc *cert.Certificate, options EncryptionOptions, embedOriginator bool) ([]byte, *cert.Certificate, error) {
	algorithm, err := options.algorithmOID()
	if err != nil {
		return nil, nil, err
	}
	entry, err := b.firstKey()
	if err != nil {
		return nil, nil, err
	}
	if rc.PublicKey == nil {
		return nil, nil, errors.New("ua: recipient has no public key")
	}
	if entry.cryptCert == nil || cert.CheckEncryptionUsage(entry.cryptCert) != nil || entry.privateKey.Curve != rc.PublicKey.Curve {
		var agreement *keyEntry
		for _, candidate := range b.keys {
			if candidate.cryptCert == nil || candidate.privateKey.Curve != rc.PublicKey.Curve || cert.CheckEncryptionUsage(candidate.cryptCert) != nil {
				continue
			}
			if entry.signCert != nil && !bytes.Equal(certificateSubject(entry.signCert), certificateSubject(candidate.cryptCert)) {
				continue
			}
			if agreement != nil {
				return nil, nil, errors.New("ua: ambiguous encryption key")
			}
			agreement = candidate
		}
		if agreement == nil {
			return nil, nil, errors.New("ua: no matching encryption key")
		}
		entry = agreement
	}

	agreement, err := options.agreementOID()
	if err != nil {
		return nil, nil, err
	}
	cmsOptions := cms.EncryptOptions{Algorithm: algorithm, AgreementAlgorithm: agreement}
	if options.StaticOriginator {
		cmsOptions.OriginatorCertificate = entry.cryptCert
		cmsOptions.EmbedOriginatorCertificate = embedOriginator
	}
	der, err := cms.EncryptWithOptions(content, []*cert.Certificate{rc}, entry.privateKey, cmsOptions)
	if err != nil {
		return nil, nil, err
	}
	return der, entry.cryptCert, nil
}

// DecryptDocument decrypts an incoming document.
// Accepts transport container bytes or raw CMS EnvelopedData DER. Static sender
// certificates are resolved from the envelope, from the container's CERTCRYPT
// sections, or from certificates loaded with AddCert. Those certificates only
// locate the originator's agreement key; they are not trusted. Decryption does
// not authenticate the sender; verify the signed plaintext separately.
func (b *Box) DecryptDocument(data []byte) ([]byte, error) {
	var err error

	cmsDER := data
	candidates := b.certificates
	// Try transport container first
	var container *transport.Container
	container, err = transport.Decode(data)
	if err == nil {
		if s := container.FindSection("UA1_CRYPT"); s != nil {
			cmsDER = s.Contents
			for _, section := range container.Sections {
				if section.Label != certCryptLabel {
					continue
				}
				// Helpers are untrusted discovery data: an unusable one is skipped,
				// and a missing originator still fails decryption below.
				helper, parseErr := cert.ParseCertificate(section.Contents)
				if parseErr != nil {
					continue
				}
				candidates = append(slices.Clone(candidates), helper)
			}
		}
	}

	msg, err := cms.ParseEnveloped(cmsDER)
	if err != nil {
		return nil, errors.New("ua: DecryptDocument: parse: " + err.Error())
	}
	decryptErrors := []error{errors.New("ua: DecryptDocument: no matching encryption key")}
	for _, entry := range b.keys {
		if entry.cryptCert == nil {
			continue
		}
		plain, decryptErr := cms.DecryptEnveloped(msg, entry.privateKey, entry.cryptCert, candidates...)
		if decryptErr == nil {
			return plain, nil
		}
		decryptErrors = append(decryptErrors, decryptErr)
	}
	return nil, errors.Join(decryptErrors...)
}

func (b *Box) signAndEncryptWithCert(content []byte, rc *cert.Certificate, opts SignOptions) ([]byte, error) {
	return b.signAndEncryptWithCertContext(context.Background(), content, rc, opts)
}

func (b *Box) signAndEncryptWithCertContext(ctx context.Context, content []byte, rc *cert.Certificate, opts SignOptions) ([]byte, error) {
	content = bytes.Clone(content)
	rawOptions := opts
	rawOptions.NoTax = true
	cmsSigned, err := b.SignDocumentWithContext(ctx, content, rawOptions)
	if err != nil {
		return nil, err
	}

	// Tax transport encrypts a UA1_SIGN section, not the bare CMS: DPS's own
	// encrypted messages decrypt to UA1_SIGN\0<len><CMS>, and Sonata stores the
	// accepted signed report the same way. NoTax keeps raw CMS inside.
	plaintext := cmsSigned
	if !opts.NoTax {
		plaintext = transport.EncodeSection(transport.Section{Label: "UA1_SIGN", Contents: cmsSigned})
	}
	// Tax transport references the static originator by issuer and serial and
	// carries its certificate only in CERTCRYPT; DPS-produced envelopes have no
	// OriginatorInfo certificates. Raw NoTax envelopes still embed it.
	cmsCrypt, senderCert, err := b.encryptWithAgreementKey(plaintext, rc, opts.Encryption, opts.NoTax)
	if err != nil {
		return nil, errors.New("ua: signAndEncryptWithCert: encrypt: " + err.Error())
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if opts.NoTax {
		return cmsCrypt, nil
	}
	header, err := opts.transportHeader(cmsSigned, content, false)
	if err != nil {
		return nil, err
	}
	// DPS requires the sender's agreement certificate in a CERTCRYPT section
	// immediately before the encrypted block, as jkurwa's tax transport emits.
	container := &transport.Container{
		Header: header,
		Sections: []transport.Section{
			{Label: certCryptLabel, Contents: bytes.Clone(senderCert.Raw)},
			{Label: "UA1_CRYPT", Contents: cmsCrypt},
		},
	}
	return transport.Encode(container), nil
}

// SignAndEncrypt signs content then encrypts the signed CMS for a recipient.
// recipientDER is the recipient's DER- or PEM-encoded certificate.
// Returns a transport container holding the sender agreement certificate
// (CERTCRYPT) followed by UA1_CRYPT, whose plaintext is a UA1_SIGN section
// carrying the signed CMS. With NoTax, it returns the EnvelopedData of the raw CMS.
func (b *Box) SignAndEncrypt(content []byte, recipientDER []byte, opts SignOptions) ([]byte, error) {
	return b.SignAndEncryptWithContext(context.Background(), content, recipientDER, opts)
}

// SignAndEncryptWithContext signs, optionally timestamps, and encrypts before
// returning output. Timestamp or cancellation failures return no partial bytes.
func (b *Box) SignAndEncryptWithContext(ctx context.Context, content, recipientDER []byte, opts SignOptions) ([]byte, error) {
	if _, err := opts.Encryption.algorithmOID(); err != nil {
		return nil, err
	}
	rc, err := cert.ParseCertificate(keystore.MaybePEM(recipientDER))
	if err != nil {
		return nil, err
	}
	return b.signAndEncryptWithCertContext(ctx, content, rc, opts)
}

func certificateSubject(c *cert.Certificate) []byte {
	if len(c.Subject.FullBytes) > 0 {
		return c.Subject.FullBytes
	}
	return c.Subject.Bytes
}
