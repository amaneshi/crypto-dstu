package cms

import (
	"bytes"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/testpki"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

func FuzzParseAndDecryptEnveloped(f *testing.F) {
	// The coordinator and every fuzz worker must use the same public fixture
	// scalar/recipient identity, so transported seeds reach actual decryption.
	key := &dstu4145.PrivateKey{Curve: dstu4145.ParamsByName("DSTU_PB_257").Curve, D: big.NewInt(2)}
	recipient := &cert.Certificate{
		SerialNumber: big.NewInt(42),
		Issuer:       asn1.RawValue{FullBytes: []byte{0x30, 0}},
		PublicKey:    key.Public(),
	}
	senderKey := &dstu4145.PrivateKey{Curve: key.Curve, D: big.NewInt(7)}
	sender, _ := testpki.IssueWithOptions(f, "Public CMS fuzz originator", nil, nil, testpki.CertificateOptions{
		Key: senderKey, Serial: big.NewInt(44),
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	for _, algorithm := range []asn1.ObjectIdentifier{OIDGost28147CFB, OIDKalyna256CFB, OIDKalyna256OFB} {
		for _, mode := range []int{0, 1, 2} {
			options := EncryptOptions{Algorithm: algorithm}
			if mode != 0 {
				options.OriginatorCertificate = sender
				options.EmbedOriginatorCertificate = mode == 1
			}
			content := []byte("Disposable CMS envelope\x00\xff")
			seed, err := EncryptWithOptions(content, []*cert.Certificate{recipient}, senderKey, options)
			require.NoError(f, err)
			message, err := ParseEnveloped(seed)
			require.NoError(f, err)
			var discovery []*cert.Certificate
			if mode == 2 {
				discovery = []*cert.Certificate{sender}
			}
			plain, err := DecryptEnveloped(message, key, recipient, discovery...)
			require.NoError(f, err)
			require.Equal(f, content, plain)
			f.Add(seed)
		}
	}
	f.Add([]byte{})
	f.Add([]byte{0x30, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		original := bytes.Clone(data)
		message, err := ParseEnveloped(data)
		require.Equal(t, original, data)
		if err != nil {
			require.Nil(t, message)
			return
		}
		withJunk, err := ParseEnveloped(append(bytes.Clone(data), 0))
		require.Error(t, err)
		require.Nil(t, withJunk)
		var discovery []*cert.Certificate
		if len(message.OriginatorCertificates) == 0 {
			discovery = []*cert.Certificate{sender}
		}
		plain, err := DecryptEnveloped(message, key, recipient, discovery...)
		if err != nil {
			require.Nil(t, plain, "failed decryption released plaintext")
		}
		// CFB/OFB content is not authenticated. Arbitrary ciphertext mutations
		// may decrypt successfully; do not assert otherwise in this harness.
		require.Equal(t, original, data, "decryption changed the caller's DER")
	})
}
