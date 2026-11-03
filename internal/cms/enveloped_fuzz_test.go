package cms

import (
	"bytes"
	"encoding/asn1"
	"math/big"
	"testing"

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
	sender, senderKey := testpki.Issue(f, "Disposable CMS fuzz originator", nil, nil, nil)
	for _, algorithm := range []asn1.ObjectIdentifier{OIDGost28147CFB, OIDKalyna256CFB, OIDKalyna256OFB} {
		for _, static := range []bool{false, true} {
			options := EncryptOptions{Algorithm: algorithm}
			if static {
				options.OriginatorCertificate = sender
				options.EmbedOriginatorCertificate = true
			}
			content := []byte("Disposable CMS envelope\x00\xff")
			seed, err := EncryptWithOptions(content, []*cert.Certificate{recipient}, senderKey, options)
			require.NoError(f, err)
			message, err := ParseEnveloped(seed)
			require.NoError(f, err)
			plain, err := DecryptEnveloped(message, key, recipient)
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
		plain, err := DecryptEnveloped(message, key, recipient)
		if err != nil {
			require.Nil(t, plain, "failed decryption released plaintext")
		}
		// CFB/OFB content is not authenticated. Arbitrary ciphertext mutations
		// may decrypt successfully; do not assert otherwise in this harness.
		require.Equal(t, original, data, "decryption changed the caller's DER")
	})
}
