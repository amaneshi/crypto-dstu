package ua

import (
	"bytes"
	"context"
	"errors"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/keystore"
	"github.com/amaneshi/crypto-dstu/internal/transport"
)

const defaultFilename = "document.xml"

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
	algorithm, err := options.algorithmOID()
	if err != nil {
		return nil, err
	}
	entry, err := b.firstKey()
	if err != nil {
		return nil, err
	}
	if rc.PublicKey == nil {
		return nil, errors.New("ua: recipient has no public key")
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
				return nil, errors.New("ua: ambiguous encryption key")
			}
			agreement = candidate
		}
		if agreement == nil {
			return nil, errors.New("ua: no matching encryption key")
		}
		entry = agreement
	}

	return cms.EncryptWithOptions(content, []*cert.Certificate{rc}, entry.privateKey, cms.EncryptOptions{Algorithm: algorithm})
}

// DecryptDocument decrypts an incoming document.
// Accepts transport container bytes or raw CMS EnvelopedData DER. Static sender
// certificates are resolved from the envelope or certificates loaded with AddCert.
// Decryption does not authenticate the sender; verify the signed plaintext separately.
func (b *Box) DecryptDocument(data []byte) ([]byte, error) {
	var err error

	cmsDER := data
	// Try transport container first
	var container *transport.Container
	container, err = transport.Decode(data)
	if err == nil {
		if s := container.FindSection("UA1_CRYPT"); s != nil {
			cmsDER = s.Contents
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
		plain, decryptErr := cms.DecryptEnveloped(msg, entry.privateKey, entry.cryptCert, b.certificates...)
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

	cmsCrypt, err := b.encryptDocumentWithOptions(cmsSigned, rc, opts.Encryption)
	if err != nil {
		return nil, errors.New("ua: signAndEncryptWithCert: encrypt: " + err.Error())
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if opts.NoTax {
		return cmsCrypt, nil
	}
	filename := opts.Filename
	if filename == "" {
		filename = defaultFilename
	}
	header := &transport.Header{
		Filename:  filename,
		SndEmail:  opts.Email,
		CerType:   "UA1",
		CRC32Sign: transport.CRC32Hex(cmsSigned),
		CRC32File: transport.CRC32Hex(content),
	}
	container := &transport.Container{
		Header: header,
		Sections: []transport.Section{
			{Label: "UA1_CRYPT", Contents: cmsCrypt},
		},
	}
	return transport.Encode(container), nil
}

// SignAndEncrypt signs content then encrypts the signed CMS for a recipient.
// recipientDER is the recipient's DER- or PEM-encoded certificate.
// Returns a transport container containing only the encrypted signed payload.
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
