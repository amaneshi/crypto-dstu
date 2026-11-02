package cms

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/stretchr/testify/require"
)

func replaceEnvelopeOriginator(t *testing.T, envelope, choice, embeddedCertificate []byte) []byte {
	t.Helper()
	inner, err := parseContentInfo(envelope, OIDEnvelopedData)
	require.NoError(t, err)
	var ed rawEnvelopedData
	_, err = asn1.Unmarshal(inner, &ed)
	require.NoError(t, err)
	if choice != nil {
		var recipient asn1.RawValue
		_, err = asn1.Unmarshal(ed.RecipientInfos.Bytes, &recipient)
		require.NoError(t, err)
		var fields []asn1.RawValue
		_, err = asn1.Unmarshal(marshalSEQ(recipient.Bytes), &fields)
		require.NoError(t, err)
		fields[1] = asn1.RawValue{FullBytes: marshalEXPLICIT(0, choice)}
		var content []byte
		for _, field := range fields {
			content = append(content, field.FullBytes...)
		}
		ed.RecipientInfos = asn1.RawValue{FullBytes: marshalSETOF(tlv(0xa1, content))}
	}
	if embeddedCertificate != nil {
		// OriginatorInfo [0] IMPLICIT contains certificates [0] IMPLICIT SET OF.
		ed.OriginatorInfo = asn1.RawValue{FullBytes: tlv(0xa0, tlv(0xa0, embeddedCertificate))}
	}
	inner, err = asn1.Marshal(ed)
	require.NoError(t, err)
	typ, err := asn1.Marshal(OIDEnvelopedData)
	require.NoError(t, err)
	return marshalSEQ(append(typ, marshalEXPLICIT(0, inner)...))
}

func TestStaticOriginatorCertificateResolution(t *testing.T) {
	sender, recipient := mustGenerateKey(t), mustGenerateKey(t)
	senderCert, recipientCert := makeCert(t, sender), makeCert(t, recipient)
	senderCert.SerialNumber = big.NewInt(1001)
	content := []byte("static originator\x00\xff")
	envelope, err := EncryptWithOriginatorCertificate(content, []*cert.Certificate{recipientCert}, sender, senderCert)
	require.NoError(t, err)
	msg, err := ParseEnveloped(envelope)
	require.NoError(t, err)
	require.NotNil(t, msg.Recipients[0].OriginatorID)
	require.Empty(t, msg.Recipients[0].OriginatorPK)
	wrongIssuer := *senderCert
	name, err := asn1.Marshal(pkix.Name{CommonName: "another issuer"}.ToRDNSequence())
	require.NoError(t, err)
	wrongIssuer.Issuer = asn1.RawValue{FullBytes: name}
	wrongSerial := *senderCert
	wrongSerial.SerialNumber = big.NewInt(1002)
	wrongKey := *senderCert
	wrongKey.PublicKey = mustGenerateKey(t).Public()
	wrongKey.Raw = []byte("different certificate with the same issuer and serial")
	wrongUsage := *senderCert
	usage, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x80}, BitLength: 1})
	require.NoError(t, err)
	wrongUsage.Extensions = []cert.Extension{{Id: oid.OIDExtKeyUsage, Value: usage}}
	for _, tc := range []struct {
		name       string
		candidates []*cert.Certificate
		failure    string
	}{
		{"missing", nil, "not found"},
		{"matching", []*cert.Certificate{senderCert}, ""},
		{"same serial different issuer", []*cert.Certificate{&wrongIssuer}, "not found"},
		{"different serial", []*cert.Certificate{&wrongSerial}, "not found"},
		{"wrong public key", []*cert.Certificate{&wrongKey}, "unwrap"},
		{"ambiguous", []*cert.Certificate{senderCert, &wrongKey}, "ambiguous"},
		{"duplicate", []*cert.Certificate{senderCert, senderCert}, ""},
		{"unrelated certificate", []*cert.Certificate{&wrongIssuer, senderCert, nil}, ""},
		{"key usage", []*cert.Certificate{&wrongUsage}, "key usage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plain, err := DecryptEnveloped(msg, recipient, recipientCert, tc.candidates...)
			if tc.failure != "" {
				require.ErrorContains(t, err, tc.failure)
				require.Empty(t, plain)
				return
			}
			require.NoError(t, err)
			require.Equal(t, content, plain)
		})
	}
}

func TestStaticOriginatorSubjectKeyIdentifier(t *testing.T) {
	sender, recipient := mustGenerateKey(t), mustGenerateKey(t)
	senderCert, recipientCert := makeCert(t, sender), makeCert(t, recipient)
	id := bytes.Repeat([]byte{0x37}, 32)
	encodedID, err := asn1.Marshal(id)
	require.NoError(t, err)
	senderCert.Extensions = []cert.Extension{{Id: oid.OIDExtSubjectKeyID, Value: encodedID}}
	content := []byte("subject key identifier")
	envelope, err := Encrypt(content, []*cert.Certificate{recipientCert}, sender)
	require.NoError(t, err)
	envelope = replaceEnvelopeOriginator(t, envelope, tlv(0x80, id), nil)
	msg, err := ParseEnveloped(envelope)
	require.NoError(t, err)
	plain, err := DecryptEnveloped(msg, recipient, recipientCert, senderCert)
	require.NoError(t, err)
	require.Equal(t, content, plain)
	senderCert.Extensions = nil
	plain, err = DecryptEnveloped(msg, recipient, recipientCert, senderCert)
	require.ErrorContains(t, err, "not found")
	require.Empty(t, plain)
}

func TestOriginatorParserRejectsMalformedChoices(t *testing.T) {
	for _, tc := range []struct {
		name   string
		choice []byte
	}{
		{"empty", nil}, {"empty ski", tlv(0x80, nil)}, {"constructed ski", tlv(0xa0, []byte{0})},
		{"unknown choice", tlv(0x82, []byte{1})}, {"empty issuer serial", marshalSEQ(nil)},
		{"extra serial field", marshalSEQ([]byte{0x30, 0, 2, 1, 1, 2, 1, 2})},
		{"negative serial", marshalSEQ([]byte{0x30, 0, 2, 1, 0xff})},
		{"zero serial", marshalSEQ([]byte{0x30, 0, 2, 1, 0})},
		{"trailing choice", append(tlv(0x80, []byte{1}), tlv(0x80, []byte{2})...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var raw asn1.RawValue
			_, err := asn1.Unmarshal(marshalEXPLICIT(0, tc.choice), &raw)
			require.NoError(t, err)
			_, _, err = parseOriginator(raw)
			require.Error(t, err)
		})
	}
}
