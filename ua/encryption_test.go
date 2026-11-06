package ua

import (
	"bytes"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/testpki"
	"github.com/amaneshi/crypto-dstu/internal/transport"
	"github.com/stretchr/testify/require"
)

func TestEncryptionProfilesThroughBox(t *testing.T) {
	root, rootKey := testpki.Issue(t, "root", nil, nil, testpki.CAExtensions(t))
	sender, senderKey := testpki.Issue(t, "sender", root, rootKey, nil)
	recipient, key := testpki.Issue(t, "recipient", root, rootKey, nil)
	box := NewBox()
	box.keys = []*keyEntry{{privateKey: senderKey, signCert: sender, cryptCert: sender}}
	receiver := NewBox()
	receiver.keys = []*keyEntry{{privateKey: key, signCert: recipient, cryptCert: recipient}}
	receiver.caCerts = append(receiver.caCerts, root)
	for _, algorithm := range []EncryptionAlgorithm{"", EncryptionGOST28147CFB, EncryptionKalyna256CFB, EncryptionKalyna256OFB} {
		name := string(algorithm)
		if name == "" {
			name = "default"
		}
		t.Run(name, func(t *testing.T) {
			options := EncryptionOptions{Algorithm: algorithm}
			content := bytes.Repeat([]byte{0x53}, 65)
			encoded, err := box.EncryptDocumentWithOptions(content, recipient.Raw, options)
			require.NoError(t, err)
			message, err := cms.ParseEnveloped(encoded)
			require.NoError(t, err)
			want, err := options.algorithmOID()
			require.NoError(t, err)
			require.Equal(t, want, message.Algorithm)
			plaintext, err := receiver.DecryptDocument(encoded)
			require.NoError(t, err)
			require.Equal(t, content, plaintext)
			for _, raw := range []bool{false, true} {
				encoded, err := box.SignAndEncrypt(content, recipient.Raw, SignOptions{NoTax: raw, Encryption: options})
				require.NoError(t, err)
				plaintext, err := receiver.DecryptDocument(encoded)
				require.NoError(t, err)
				verified, err := receiver.UnsignDocument(plaintext)
				require.NoError(t, err)
				require.Equal(t, content, verified.Content)
			}
		})
	}
	invalid := EncryptionOptions{Algorithm: "unknown"}
	output, err := box.EncryptDocumentWithOptions([]byte("data"), recipient.Raw, invalid)
	require.ErrorContains(t, err, "unsupported encryption")
	require.Nil(t, output)
	output, err = box.SignAndEncrypt([]byte("data"), recipient.Raw, SignOptions{Encryption: invalid})
	require.ErrorContains(t, err, "unsupported encryption")
	require.Nil(t, output)
}

func TestEncryptionRejectsUnknownAndIncompatibleAgreement(t *testing.T) {
	box := NewBox()
	for _, options := range []EncryptionOptions{
		{Algorithm: EncryptionKalyna256CFB, Agreement: "unknown"},
		{Algorithm: EncryptionGOST28147CFB, Agreement: AgreementStandardDH},
	} {
		output, err := box.EncryptDocumentWithOptions([]byte("data"), nil, options)
		require.Error(t, err)
		require.Nil(t, output)
		output, err = box.SignAndEncrypt([]byte("data"), nil, SignOptions{Encryption: options})
		require.Error(t, err)
		require.Nil(t, output)
	}
}

func TestStaticOriginatorEmbedsAgreementCertificate(t *testing.T) {
	sender, key := testpki.Issue(t, "sender", nil, nil, nil)
	recipient, recipientKey := testpki.Issue(t, "recipient", nil, nil, nil)
	box := NewBox()
	box.keys = []*keyEntry{{privateKey: key, signCert: sender, cryptCert: sender}}
	receiver := NewBox()
	receiver.keys = []*keyEntry{{privateKey: recipientKey, cryptCert: recipient}}
	for _, algorithm := range []EncryptionAlgorithm{EncryptionGOST28147CFB, EncryptionKalyna256CFB, EncryptionKalyna256OFB} {
		t.Run(string(algorithm), func(t *testing.T) {
			content := []byte("static certificate discovery")
			encoded, err := box.EncryptDocumentWithOptions(content, recipient.Raw, EncryptionOptions{Algorithm: algorithm, StaticOriginator: true})
			require.NoError(t, err)
			message, err := cms.ParseEnveloped(encoded)
			require.NoError(t, err)
			require.Len(t, message.OriginatorCertificates, 1)
			require.Equal(t, sender.Raw, message.OriginatorCertificates[0].Raw)
			plain, err := receiver.DecryptDocument(encoded)
			require.NoError(t, err)
			require.Equal(t, content, plain)
			require.Empty(t, receiver.caCerts)
		})
	}
}

// DPS rejects tax transport without the sender's agreement certificate in a
// CERTCRYPT section before UA1_CRYPT ("відсутній сертифікат для розшифрування
// перед зашифрованим блоком"). jkurwa's Message.as_transport emits the same
// order with the sender's encryption certificate, never the recipient's.
func TestTaxTransportCarriesSenderAgreementCertificate(t *testing.T) {
	sender, senderKey := testpki.Issue(t, "sender", nil, nil, nil)
	recipient, recipientKey := testpki.Issue(t, "recipient", nil, nil, nil)
	box := NewBox()
	box.keys = []*keyEntry{{privateKey: senderKey, signCert: sender, cryptCert: sender}}
	receiver := NewBox()
	receiver.keys = []*keyEntry{{privateKey: recipientKey, cryptCert: recipient}}
	content := []byte("tax transport sender certificate")
	for _, static := range []bool{false, true} {
		encoded, err := box.SignAndEncrypt(content, recipient.Raw, SignOptions{
			Filename:   "report.xml",
			Encryption: EncryptionOptions{StaticOriginator: static},
		})
		require.NoError(t, err)
		container, err := transport.Decode(encoded)
		require.NoError(t, err)
		require.NotNil(t, container.Header)
		require.Len(t, container.Sections, 2)
		require.Equal(t, "CERTCRYPT", container.Sections[0].Label)
		require.Equal(t, sender.Raw, container.Sections[0].Contents)
		require.Equal(t, "UA1_CRYPT", container.Sections[1].Label)
		// DPS-produced envelopes have no OriginatorInfo certificates; the
		// static originator is found through CERTCRYPT, not the envelope.
		envelope, err := cms.ParseEnveloped(container.Sections[1].Contents)
		require.NoError(t, err)
		require.Empty(t, envelope.OriginatorCertificates)
		require.Empty(t, receiver.certificates)
		// DPS's own encrypted receipts decrypt to UA1_SIGN\0<len><CMS>; the
		// signed report must be wrapped the same way inside UA1_CRYPT.
		signed, err := receiver.DecryptDocument(encoded)
		require.NoError(t, err)
		inner, err := transport.DecodeSections(signed)
		require.NoError(t, err)
		require.Len(t, inner, 1)
		require.Equal(t, "UA1_SIGN", inner[0].Label)
		message, err := cms.ParseSigned(inner[0].Contents)
		require.NoError(t, err)
		require.Equal(t, content, message.Content)
		receiver.caCerts = []*cert.Certificate{sender}
		verified, err := receiver.UnsignDocument(signed)
		receiver.caCerts = nil
		require.NoError(t, err)
		require.Equal(t, content, verified.Content)
	}
	raw, err := box.SignAndEncrypt(content, recipient.Raw, SignOptions{NoTax: true})
	require.NoError(t, err)
	_, err = cms.ParseEnveloped(raw)
	require.NoError(t, err, "NoTax output remains a bare EnvelopedData")
	plain, err := receiver.DecryptDocument(raw)
	require.NoError(t, err)
	_, err = cms.ParseSigned(plain)
	require.NoError(t, err, "NoTax plaintext remains bare CMS")
}

// CERTCRYPT is untrusted discovery data for the static originator certificate:
// it lets a receiver decrypt without the originator embedded in the envelope or
// preloaded with AddCert, and a wrong or malformed helper does not substitute.
func TestDecryptResolvesOriginatorFromCertCrypt(t *testing.T) {
	sender, senderKey := testpki.Issue(t, "sender", nil, nil, nil)
	recipient, recipientKey := testpki.Issue(t, "recipient", nil, nil, nil)
	unrelated, _ := testpki.Issue(t, "unrelated", nil, nil, nil)
	receiver := NewBox()
	receiver.keys = []*keyEntry{{privateKey: recipientKey, cryptCert: recipient}}
	algorithm, err := EncryptionOptions{}.algorithmOID()
	require.NoError(t, err)
	content := []byte("originator from CERTCRYPT")
	envelope, err := cms.EncryptWithOptions(content, []*cert.Certificate{recipient}, senderKey, cms.EncryptOptions{
		Algorithm:             algorithm,
		OriginatorCertificate: sender,
	})
	require.NoError(t, err)
	wrap := func(helpers ...[]byte) []byte {
		var sections []transport.Section
		for _, helper := range helpers {
			sections = append(sections, transport.Section{Label: "CERTCRYPT", Contents: helper})
		}
		sections = append(sections, transport.Section{Label: "UA1_CRYPT", Contents: envelope})
		return transport.Encode(&transport.Container{Header: &transport.Header{Filename: "doc.xml"}, Sections: sections})
	}

	_, err = receiver.DecryptDocument(envelope)
	require.Error(t, err, "originator is neither embedded nor known")
	_, err = receiver.DecryptDocument(wrap(unrelated.Raw))
	require.Error(t, err)
	_, err = receiver.DecryptDocument(wrap([]byte{0x30, 0x03, 0x02, 0x01, 0x01}))
	require.Error(t, err)

	plain, err := receiver.DecryptDocument(wrap([]byte{0x30, 0x00}, sender.Raw))
	require.NoError(t, err)
	require.Equal(t, content, plain)
	require.Empty(t, receiver.certificates, "helpers are not retained")
	require.Empty(t, receiver.caCerts, "helpers are not trusted")
}

// DPS routes gateway replies by the transport header EDRPOU; Sonata writes it
// and a reply to a request without it was addressed RCV_EDRPOU=00000000.
func TestTaxTransportHeaderEDRPOU(t *testing.T) {
	sender, senderKey := testpki.Issue(t, "sender", nil, nil, nil)
	recipient, _ := testpki.Issue(t, "recipient", nil, nil, nil)
	box := NewBox()
	box.keys = []*keyEntry{{privateKey: senderKey, signCert: sender, cryptCert: sender}}
	options := SignOptions{Filename: "report.xml", Email: "sender@example.test", EDRPOU: "1234567890"}
	encoded, err := box.SignAndEncrypt([]byte("header"), recipient.Raw, options)
	require.NoError(t, err)
	container, err := transport.Decode(encoded)
	require.NoError(t, err)
	require.Equal(t, "1234567890", container.Header.EDRPOU)
	require.Equal(t, "sender@example.test", container.Header.SndEmail)

	signed, err := box.SignDocument([]byte("header"), options)
	require.NoError(t, err)
	box.caCerts = []*cert.Certificate{sender}
	result, err := box.UnsignDocument(signed)
	box.caCerts = nil
	require.NoError(t, err)
	require.Equal(t, "1234567890", result.Header.EDRPOU)

	for _, bad := range []SignOptions{
		{EDRPOU: "1234567"},
		{EDRPOU: "12345678901"},
		{EDRPOU: "12345678A"},
		{EDRPOU: "12345678\r\nRESULT=0"},
		{Filename: "a.xml\r\nEDRPOU=1"},
		{Email: "x@example.test\x00"},
	} {
		output, err := box.SignAndEncrypt([]byte("header"), recipient.Raw, bad)
		require.Error(t, err)
		require.Nil(t, output)
		output, err = box.SignDocument([]byte("header"), bad)
		require.Error(t, err)
		require.Nil(t, output)
	}
}
