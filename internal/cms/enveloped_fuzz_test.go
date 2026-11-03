package cms

import (
	"bytes"
	"encoding/asn1"
	"encoding/json"
	"math/big"
	"os"
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
	data, err := os.ReadFile("testdata/iit-onb-kalyna/DSTU_ONB_173.json")
	require.NoError(f, err)
	var fixture struct {
		SenderCertificate, RecipientCertificate []byte
		Samples                                 []struct{ Envelope []byte }
	}
	require.NoError(f, json.Unmarshal(data, &fixture))
	onbSender, err := cert.ParseCertificate(fixture.SenderCertificate)
	require.NoError(f, err)
	onbRecipient, err := cert.ParseCertificate(fixture.RecipientCertificate)
	require.NoError(f, err)
	onbCurve := onbRecipient.PublicKey.Curve
	d := new(big.Int).Lsh(big.NewInt(1), uint(new(big.Int).SetBytes(onbCurve.N).BitLen()-2))
	d.Add(d, big.NewInt(0x12345))
	onbKey := &dstu4145.PrivateKey{Curve: onbCurve, D: d}
	onbSenderKey := &dstu4145.PrivateKey{Curve: onbCurve, D: new(big.Int).Add(d, big.NewInt(0x13579))}
	cofactorDER, err := asn1.Marshal(OIDKupynaDH)
	require.NoError(f, err)
	standardDER, err := asn1.Marshal(OIDKupynaStandardDH)
	require.NoError(f, err)
	for _, sample := range fixture.Samples {
		corrected := bytes.ReplaceAll(sample.Envelope, cofactorDER, standardDER)
		parsed, err := ParseEnveloped(corrected)
		require.NoError(f, err)
		_, err = DecryptEnveloped(parsed, onbKey, onbRecipient, onbSender)
		require.NoError(f, err)
		f.Add(sample.Envelope)
		f.Add(corrected)
	}
	for _, algorithm := range []asn1.ObjectIdentifier{OIDKalyna256CFB, OIDKalyna256OFB} {
		for _, embedded := range []bool{false, true} {
			options := EncryptOptions{Algorithm: algorithm, AgreementAlgorithm: OIDKupynaStandardDH}
			if embedded {
				options.OriginatorCertificate = onbSender
				options.EmbedOriginatorCertificate = true
			}
			seed, err := EncryptWithOptions([]byte("ONB standard-DH fuzz"), []*cert.Certificate{onbRecipient}, onbSenderKey, options)
			require.NoError(f, err)
			f.Add(seed)
		}
	}
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
			discovery = []*cert.Certificate{sender, onbSender}
		}
		plain, err := DecryptEnveloped(message, key, recipient, discovery...)
		if err != nil {
			require.Nil(t, plain, "failed decryption released plaintext")
		}
		plain, err = DecryptEnveloped(message, onbKey, onbRecipient, discovery...)
		if err != nil {
			require.Nil(t, plain, "failed ONB decryption released plaintext")
		}
		// CFB/OFB content is not authenticated. Arbitrary ciphertext mutations
		// may decrypt successfully; do not assert otherwise in this harness.
		require.Equal(t, original, data, "decryption changed the caller's DER")
	})
}
