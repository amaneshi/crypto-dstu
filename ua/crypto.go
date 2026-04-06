package ua

import (
	"errors"

	"crypto-dstu/cert"
	"crypto-dstu/cms"
	"crypto-dstu/keystore"
	"crypto-dstu/transport"
)

// EncryptDocument encrypts content for a recipient using ECDH+GOST28147.
// Returns raw CMS EnvelopedData DER bytes.
func (b *Box) EncryptDocument(content []byte, recipientCert *cert.Certificate) ([]byte, error) {
	entry, err := b.firstKey()
	if err != nil {
		return nil, err
	}
	return cms.Encrypt(content, []*cert.Certificate{recipientCert}, entry.PrivateKey)
}

// DecryptDocument decrypts an incoming document.
// Accepts transport container bytes or raw CMS EnvelopedData DER.
func (b *Box) DecryptDocument(data []byte) ([]byte, error) {
	entry, err := b.firstKey()
	if err != nil {
		return nil, err
	}
	if entry.CryptCert == nil {
		return nil, errors.New("ua: DecryptDocument: no encryption certificate loaded")
	}

	cmsDER := data
	// Try transport container first
	if container, err := transport.Decode(data); err == nil {
		if s := container.FindSection("UA1_CRYPT"); s != nil {
			cmsDER = s.Contents
		}
	}

	msg, err := cms.ParseEnveloped(cmsDER)
	if err != nil {
		return nil, errors.New("ua: DecryptDocument: parse: " + err.Error())
	}
	return cms.DecryptEnveloped(msg, entry.PrivateKey, entry.CryptCert)
}

// EncryptForRecipientDER is like EncryptDocument but accepts raw DER/PEM cert bytes.
func (b *Box) EncryptForRecipientDER(content []byte, recipientDER []byte) ([]byte, error) {
	recipientDER = keystore.MaybePEM(recipientDER)
	rc, err := cert.ParseCertificate(recipientDER)
	if err != nil {
		return nil, errors.New("ua: EncryptForRecipientDER: parse cert: " + err.Error())
	}
	return b.EncryptDocument(content, rc)
}

// SignAndEncryptDER is like SignAndEncrypt but accepts raw DER/PEM cert bytes for the recipient.
func (b *Box) SignAndEncryptDER(content []byte, recipientDER []byte, opts SignOptions) ([]byte, error) {
	recipientDER = keystore.MaybePEM(recipientDER)
	rc, err := cert.ParseCertificate(recipientDER)
	if err != nil {
		return nil, errors.New("ua: SignAndEncryptDER: parse cert: " + err.Error())
	}
	return b.SignAndEncrypt(content, rc, opts)
}

// SignAndEncrypt signs content then encrypts the signed CMS for a recipient.
// Returns a transport container with both sign and crypt sections.
func (b *Box) SignAndEncrypt(content []byte, recipientCert *cert.Certificate, opts SignOptions) ([]byte, error) {
	entry, err := b.firstKey()
	if err != nil {
		return nil, err
	}
	if entry.SignCert == nil {
		return nil, errors.New("ua: SignAndEncrypt: no signing certificate loaded")
	}

	// 1. Sign
	cmsSigned, err := cms.Sign(content, entry.PrivateKey, entry.SignCert, cms.SignOptions{Detached: opts.Detached})
	if err != nil {
		return nil, errors.New("ua: SignAndEncrypt: sign: " + err.Error())
	}

	// 2. Encrypt the signed blob
	cmsCrypt, err := cms.Encrypt(cmsSigned, []*cert.Certificate{recipientCert}, entry.PrivateKey)
	if err != nil {
		return nil, errors.New("ua: SignAndEncrypt: encrypt: " + err.Error())
	}

	if opts.NoTax {
		return cmsCrypt, nil
	}

	filename := opts.Filename
	if filename == "" {
		filename = "document.xml"
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
			{Label: "UA1_SIGN", Contents: cmsSigned},
			{Label: "UA1_CRYPT", Contents: cmsCrypt},
		},
	}
	return transport.Encode(container), nil
}
