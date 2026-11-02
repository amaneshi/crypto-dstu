package ua

import (
	"bytes"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/testpki"
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
