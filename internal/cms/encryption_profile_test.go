package cms

import (
	"bytes"
	"encoding/asn1"
	"testing"

	"crypto-dstu/internal/cert"
	"github.com/stretchr/testify/require"
)

func TestKalynaProfileRejectsMalformedParameters(t *testing.T) {
	key := mustGenerateKey(t)
	recipient := makeCert(t, key)
	encoded, err := EncryptWithOptions([]byte("data"), []*cert.Certificate{recipient}, key, EncryptOptions{Algorithm: OIDKalyna256CFB})
	require.NoError(t, err)
	inner, err := parseContentInfo(encoded, OIDEnvelopedData)
	require.NoError(t, err)
	for _, tc := range []struct {
		name   string
		change func(*rawEnvelopedData)
	}{
		{"short IV", func(ed *rawEnvelopedData) {
			ed.EncryptedContentInfo.ContentEncryptionAlgorithm.Parameters.IV = make([]byte, 31)
		}},
		{"unexpected DKE", func(ed *rawEnvelopedData) {
			ed.EncryptedContentInfo.ContentEncryptionAlgorithm.Parameters.DKE = make([]byte, 64)
		}},
		{"unknown cipher", func(ed *rawEnvelopedData) {
			ed.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ed rawEnvelopedData
			_, err := asn1.Unmarshal(inner, &ed)
			require.NoError(t, err)
			tc.change(&ed)
			changed, err := asn1.Marshal(ed)
			require.NoError(t, err)
			typ, err := asn1.Marshal(OIDEnvelopedData)
			require.NoError(t, err)
			_, err = ParseEnveloped(marshalSEQ(append(typ, marshalEXPLICIT(0, changed)...)))
			require.Error(t, err)
		})
	}
	original, err := asn1.Marshal(OIDKupynaDH)
	require.NoError(t, err)
	replacement, err := asn1.Marshal(OIDDSTU4145DH)
	require.NoError(t, err)
	_, err = ParseEnveloped(bytes.Replace(encoded, original, replacement, 1))
	require.Error(t, err)
	original, err = asn1.Marshal(AlgorithmIdentifier{Algorithm: OIDKalynaWrap, Parameters: asn1.RawValue{Tag: asn1.TagNull}})
	require.NoError(t, err)
	replacement, err = asn1.Marshal(AlgorithmIdentifier{Algorithm: OIDKalynaWrap, Parameters: asn1.RawValue{Tag: asn1.TagOctetString}})
	require.NoError(t, err)
	require.Equal(t, 1, bytes.Count(encoded, original))
	_, err = ParseEnveloped(bytes.Replace(encoded, original, replacement, 1))
	require.Error(t, err)
}
