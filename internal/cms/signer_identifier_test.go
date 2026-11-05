package cms

import (
	"bytes"
	"encoding/asn1"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/stretchr/testify/require"
)

// withSubjectKeyID gives c a single subjectKeyIdentifier extension.
func withSubjectKeyID(t *testing.T, c *cert.Certificate, id []byte) *cert.Certificate {
	t.Helper()
	encoded, err := asn1.Marshal(id)
	require.NoError(t, err)
	clone := *c
	clone.Extensions = []cert.Extension{{Id: oid.OIDExtSubjectKeyID, Value: encoded}}
	return &clone
}

// replaceSignerSID swaps the encoded SignerIdentifier and version of the only
// SignerInfo. The SID is not covered by the signature, so the result remains a
// valid signature whenever the new identifier still resolves to the signer.
func replaceSignerSID(t *testing.T, der []byte, version int, sid []byte) []byte {
	t.Helper()
	inner, err := parseContentInfo(der, OIDSignedData)
	require.NoError(t, err)
	var outer asn1.RawValue
	_, err = asn1.Unmarshal(inner, &outer)
	require.NoError(t, err)
	// Locate the trailing SignerInfos SET and its single SignerInfo.
	var fields []asn1.RawValue
	for rest := outer.Bytes; len(rest) > 0; {
		var field asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &field)
		require.NoError(t, err)
		fields = append(fields, field)
	}
	setField := fields[len(fields)-1]
	var signerSeq asn1.RawValue
	_, err = asn1.Unmarshal(setField.Bytes, &signerSeq)
	require.NoError(t, err)
	var oldVersion int
	rest, err := asn1.Unmarshal(signerSeq.Bytes, &oldVersion)
	require.NoError(t, err)
	var oldSID asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &oldSID)
	require.NoError(t, err)
	versionDER, err := asn1.Marshal(version)
	require.NoError(t, err)
	signer := marshalSEQ(bytes.Join([][]byte{versionDER, sid, rest}, nil))
	var body []byte
	for _, field := range fields[:len(fields)-1] {
		body = append(body, field.FullBytes...)
	}
	body = append(body, marshalSETOF(signer)...)
	typ, err := asn1.Marshal(OIDSignedData)
	require.NoError(t, err)
	return marshalSEQ(append(typ, marshalEXPLICIT(0, marshalSEQ(body))...))
}

func TestSignerInfoSubjectKeyIdentifierForms(t *testing.T) {
	key := mustGenerateKey(t)
	id := bytes.Repeat([]byte{0x4a}, 32)
	signer := withSubjectKeyID(t, makeCert(t, key), id)
	content := []byte("key identifier signer")
	raw, err := Sign(content, key, signer, SignOptions{})
	require.NoError(t, err)

	for _, tc := range []struct {
		name     string
		sid      []byte
		explicit bool
	}{
		// RFC 5652 [0] IMPLICIT SubjectKeyIdentifier.
		{"implicit", tlv(0x80, id), false},
		// DPS receipts use [0] EXPLICIT around the OCTET STRING.
		{"explicit", tlv(0xa0, tlv(0x04, id)), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			der := replaceSignerSID(t, raw, 3, tc.sid)
			msg, err := ParseSigned(der)
			require.NoError(t, err)
			require.Equal(t, id, msg.rawSigners[0].SubjectKeyID)
			require.Equal(t, tc.explicit, msg.rawSigners[0].SubjectKeyIDExplicit)
			msg.Certificates = append(msg.Certificates, signer)
			ResolveCertificates(msg)
			require.Same(t, signer, msg.Signers[0].Certificate)
			require.NoError(t, VerifySigned(msg, nil, nil))
			require.True(t, msg.Signers[0].Valid)

			// Re-encoding (as timestamping does) preserves the producer's form.
			encoded, err := marshalSignerInfo(msg.rawSigners[0])
			require.NoError(t, err)
			require.True(t, bytes.Contains(der, encoded))
		})
	}
}

func TestSignerInfoSubjectKeyIdentifierResolution(t *testing.T) {
	key := mustGenerateKey(t)
	id := bytes.Repeat([]byte{0x4a}, 32)
	signer := withSubjectKeyID(t, makeCert(t, key), id)
	content := []byte("key identifier resolution")
	raw, err := Sign(content, key, signer, SignOptions{})
	require.NoError(t, err)
	der := replaceSignerSID(t, raw, 3, tlv(0xa0, tlv(0x04, id)))

	t.Run("unknown identifier", func(t *testing.T) {
		other := replaceSignerSID(t, raw, 3, tlv(0x80, bytes.Repeat([]byte{0x11}, 32)))
		msg, err := ParseSigned(other)
		require.NoError(t, err)
		msg.Certificates = append(msg.Certificates, signer)
		ResolveCertificates(msg)
		require.Nil(t, msg.Signers[0].Certificate)
		require.Error(t, VerifySigned(msg, nil, nil))
		require.False(t, msg.Signers[0].Valid)
	})

	t.Run("certificate without extension", func(t *testing.T) {
		msg, err := ParseSigned(der)
		require.NoError(t, err)
		msg.Certificates = []*cert.Certificate{makeCert(t, key)}
		ResolveCertificates(msg)
		require.Nil(t, msg.Signers[0].Certificate)
	})

	t.Run("exact duplicates resolve", func(t *testing.T) {
		msg, err := ParseSigned(der)
		require.NoError(t, err)
		duplicate := *signer
		msg.Certificates = []*cert.Certificate{signer, &duplicate}
		require.NoError(t, VerifySigned(msg, nil, nil))
		require.Same(t, signer, msg.Signers[0].Certificate)
		require.True(t, msg.Signers[0].Valid)
	})

	t.Run("distinct certificates sharing identifier are ambiguous", func(t *testing.T) {
		msg, err := ParseSigned(der)
		require.NoError(t, err)
		impostorKey := mustGenerateKey(t)
		impostor := withSubjectKeyID(t, makeCert(t, impostorKey), id)
		impostor.Raw = []byte{0x30, 0x03, 0x02, 0x01, 0x07}
		msg.Certificates = []*cert.Certificate{impostor, signer}
		require.Error(t, VerifySigned(msg, nil, nil))
		require.Nil(t, msg.Signers[0].Certificate)
		require.False(t, msg.Signers[0].Valid)
	})
}

func TestSignerInfoIdentifierRejectsMalformedChoices(t *testing.T) {
	key := mustGenerateKey(t)
	signer := makeCert(t, key)
	raw, err := Sign([]byte("malformed sid"), key, signer, SignOptions{})
	require.NoError(t, err)
	issuerSerial, err := asn1.Marshal(IssuerAndSerialNumber{Issuer: signer.Issuer, SerialNumber: signer.SerialNumber})
	require.NoError(t, err)
	id := bytes.Repeat([]byte{0x4a}, 20)
	trailingSerial := append([]byte(nil), issuerSerial...)
	trailingSerial = tlv(0x30, append(trailingSerial[2:], 0x05, 0x00))

	for _, tc := range []struct {
		name    string
		version int
		sid     []byte
		message string
	}{
		{"key identifier with version 1", 1, tlv(0x80, id), "requires version 3"},
		{"explicit key identifier with version 1", 1, tlv(0xa0, tlv(0x04, id)), "requires version 3"},
		{"issuer serial with version 3", 3, issuerSerial, "requires version 1"},
		{"empty implicit identifier", 3, tlv(0x80, nil), "invalid SignerInfo subjectKeyIdentifier"},
		{"empty explicit identifier", 3, tlv(0xa0, tlv(0x04, nil)), "invalid SignerInfo subjectKeyIdentifier"},
		{"explicit identifier not octet string", 3, tlv(0xa0, tlv(0x02, id)), "invalid SignerInfo subjectKeyIdentifier"},
		{"explicit identifier trailing data", 3, tlv(0xa0, append(tlv(0x04, id), 0x05, 0x00)), "invalid SignerInfo subjectKeyIdentifier"},
		{"unknown choice", 3, tlv(0x81, id), "unsupported SignerInfo SID choice"},
		{"issuer serial trailing field", 1, trailingSerial, "trailing SignerInfo SID fields"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSigned(replaceSignerSID(t, raw, tc.version, tc.sid))
			require.ErrorContains(t, err, tc.message)
		})
	}
}
