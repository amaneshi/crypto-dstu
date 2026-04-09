package ua

import (
	"errors"

	"crypto-dstu/internal/cert"
	"crypto-dstu/internal/cms"
	"crypto-dstu/internal/keystore"
	"crypto-dstu/internal/transport"
)

const defaultFilename = "document.xml"

// EncryptDocument encrypts content for a recipient using ECDH+GOST28147.
// recipientDER is the recipient's DER- or PEM-encoded certificate.
// Returns raw CMS EnvelopedData DER bytes.
func (b *Box) EncryptDocument(content []byte, recipientDER []byte) ([]byte, error) {
	recipientDER = keystore.MaybePEM(recipientDER)
	rc, err := cert.ParseCertificate(recipientDER)
	if err != nil {
		return nil, errors.New("ua: EncryptDocument: parse recipient cert: " + err.Error())
	}
	return b.encryptDocument(content, rc)
}

func (b *Box) encryptDocument(content []byte, rc *cert.Certificate) ([]byte, error) {
	entry, err := b.firstKey()
	if err != nil {
		return nil, err
	}
	return cms.Encrypt(content, []*cert.Certificate{rc}, entry.privateKey)
}

// DecryptDocument decrypts an incoming document.
// Accepts transport container bytes or raw CMS EnvelopedData DER.
func (b *Box) DecryptDocument(data []byte) ([]byte, error) {
	entry, err := b.firstKey()
	if err != nil {
		return nil, err
	}
	if entry.cryptCert == nil {
		return nil, errors.New("ua: DecryptDocument: no encryption certificate loaded")
	}

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
	return cms.DecryptEnveloped(msg, entry.privateKey, entry.cryptCert)
}

func (b *Box) signAndEncryptWithCert(content []byte, rc *cert.Certificate, opts SignOptions) ([]byte, error) {
	entry, err := b.firstKey()
	if err != nil {
		return nil, err
	}
	if entry.signCert == nil {
		return nil, errors.New("ua: signAndEncryptWithCert: no signing certificate loaded")
	}
	cmsSigned, err := cms.Sign(content, entry.privateKey, entry.signCert, cms.SignOptions{Detached: opts.Detached})
	if err != nil {
		return nil, errors.New("ua: signAndEncryptWithCert: sign: " + err.Error())
	}
	cmsCrypt, err := b.encryptDocument(cmsSigned, rc)
	if err != nil {
		return nil, errors.New("ua: signAndEncryptWithCert: encrypt: " + err.Error())
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
			{Label: "UA1_SIGN", Contents: cmsSigned},
			{Label: "UA1_CRYPT", Contents: cmsCrypt},
		},
	}
	return transport.Encode(container), nil
}

// SignAndEncrypt signs content then encrypts the signed CMS for a recipient.
// recipientDER is the recipient's DER- or PEM-encoded certificate.
// Returns a transport container with both sign and crypt sections.
func (b *Box) SignAndEncrypt(content []byte, recipientDER []byte, opts SignOptions) ([]byte, error) {
	entry, err := b.firstKey()
	if err != nil {
		return nil, err
	}
	if entry.signCert == nil {
		return nil, errors.New("ua: SignAndEncrypt: no signing certificate loaded")
	}

	recipientDER = keystore.MaybePEM(recipientDER)
	rc, err := cert.ParseCertificate(recipientDER)
	if err != nil {
		return nil, errors.New("ua: SignAndEncrypt: parse recipient cert: " + err.Error())
	}

	// 1. Sign
	cmsSigned, err := cms.Sign(content, entry.privateKey, entry.signCert, cms.SignOptions{Detached: opts.Detached})
	if err != nil {
		return nil, errors.New("ua: SignAndEncrypt: sign: " + err.Error())
	}

	// 2. Encrypt the signed blob
	cmsCrypt, err := b.encryptDocument(cmsSigned, rc)
	if err != nil {
		return nil, errors.New("ua: SignAndEncrypt: encrypt: " + err.Error())
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
			{Label: "UA1_SIGN", Contents: cmsSigned},
			{Label: "UA1_CRYPT", Contents: cmsCrypt},
		},
	}
	return transport.Encode(container), nil
}
