package testiit

import (
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/require"
)

func rawChildren(t testing.TB, encoded []byte) []asn1.RawValue {
	t.Helper()
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(encoded, &outer)
	require.NoError(t, err)
	require.Empty(t, rest)
	var children []asn1.RawValue
	remaining := outer.Bytes
	for len(remaining) > 0 {
		var value asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &value)
		require.NoError(t, err)
		children = append(children, value)
	}
	return children
}

func signedDataFields(t testing.TB, der []byte) []asn1.RawValue {
	t.Helper()
	ci := rawChildren(t, der)
	require.Len(t, ci, 2)
	sd := rawChildren(t, ci[1].Bytes)
	require.GreaterOrEqual(t, len(sd), 4)
	return sd
}

// SignerDigest independently reads the original CMS SignerInfo digest OID.
// This does not verify signature validity.
func SignerDigest(t testing.TB, der []byte) asn1.ObjectIdentifier {
	t.Helper()
	sd := signedDataFields(t, der)
	signers := rawChildren(t, sd[len(sd)-1].FullBytes)
	require.Len(t, signers, 1)
	signer := rawChildren(t, signers[0].FullBytes)
	require.GreaterOrEqual(t, len(signer), 5)
	var algorithm algorithmIdentifier
	rest, err := asn1.Unmarshal(signer[2].FullBytes, &algorithm)
	require.NoError(t, err)
	require.Empty(t, rest)
	return algorithm.Algorithm
}

// SignerSignatureAlgorithm reads the signature OID without enabling a profile.
func SignerSignatureAlgorithm(t testing.TB, der []byte) asn1.ObjectIdentifier {
	t.Helper()
	sd := signedDataFields(t, der)
	signers := rawChildren(t, sd[len(sd)-1].FullBytes)
	require.Len(t, signers, 1)
	signer := rawChildren(t, signers[0].FullBytes)
	require.GreaterOrEqual(t, len(signer), 5)
	index := 3
	if signer[index].Class == 2 && signer[index].Tag == 0 {
		index++
	}
	var algorithm algorithmIdentifier
	rest, err := asn1.Unmarshal(signer[index].FullBytes, &algorithm)
	require.NoError(t, err)
	require.Empty(t, rest)
	return algorithm.Algorithm
}

// DigestSet independently reads all container-level CMS digest identifiers.
func DigestSet(t testing.TB, der []byte) []asn1.ObjectIdentifier {
	t.Helper()
	sd := signedDataFields(t, der)
	var algorithms []asn1.ObjectIdentifier
	for _, encoded := range rawChildren(t, sd[1].FullBytes) {
		var algorithm algorithmIdentifier
		rest, err := asn1.Unmarshal(encoded.FullBytes, &algorithm)
		require.NoError(t, err)
		require.Empty(t, rest)
		algorithms = append(algorithms, algorithm.Algorithm)
	}
	return algorithms
}

// HasEmbeddedContent distinguishes an empty attached payload from detached CMS.
func HasEmbeddedContent(t testing.TB, der []byte) bool {
	t.Helper()
	sd := signedDataFields(t, der)
	fields := rawChildren(t, sd[2].FullBytes)
	require.True(t, len(fields) == 1 || len(fields) == 2)
	if len(fields) == 1 {
		return false
	}
	require.Equal(t, 2, fields[1].Class)
	require.Equal(t, 0, fields[1].Tag)
	return true
}
