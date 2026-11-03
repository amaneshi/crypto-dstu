package testiit

import (
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/require"
)

// CSRSignatureData reads exact original DER and signature bytes for independent checks.
func CSRSignatureData(t testing.TB, der []byte) (cri, spki, signature []byte, algorithm asn1.ObjectIdentifier) {
	t.Helper()
	outer := rawChildren(t, der)
	require.Len(t, outer, 3)
	fields := rawChildren(t, outer[0].FullBytes)
	require.Len(t, fields, 4)
	var aid algorithmIdentifier
	rest, err := asn1.Unmarshal(outer[1].FullBytes, &aid)
	require.NoError(t, err)
	require.Empty(t, rest)
	var bits asn1.BitString
	rest, err = asn1.Unmarshal(outer[2].FullBytes, &bits)
	require.NoError(t, err)
	require.Empty(t, rest)
	require.Equal(t, len(bits.Bytes)*8, bits.BitLength)
	rest, err = asn1.Unmarshal(bits.Bytes, &signature)
	require.NoError(t, err)
	require.Empty(t, rest)
	return outer[0].FullBytes, fields[2].FullBytes, signature, aid.Algorithm
}

// CertificateSPKI reads the complete original SPKI of a disposable v3 certificate.
func CertificateSPKI(t testing.TB, der []byte) []byte {
	t.Helper()
	outer := rawChildren(t, der)
	require.Len(t, outer, 3)
	fields := rawChildren(t, outer[0].FullBytes)
	require.GreaterOrEqual(t, len(fields), 7)
	require.Equal(t, 2, fields[0].Class)
	require.Equal(t, 0, fields[0].Tag)
	return fields[6].FullBytes
}
