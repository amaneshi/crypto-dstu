package csr_test

import (
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/require"

	"crypto-dstu/internal/csr"
	"crypto-dstu/internal/oid"
	"crypto-dstu/pkg/dstu4145"
	"crypto-dstu/pkg/ec"
)

// TestCreateParse verifies that a CSR created with NewRequest can be parsed back.
func TestCreateParse(t *testing.T) {
	priv, err := dstu4145.GenerateKey(ec.DSTU_PB_257())
	require.NoError(t, err)

	req := &csr.Request{
		Subject: []csr.AttributeTypeAndValue{
			{Type: oid.OIDCommonName, Value: "Test User"},
			{Type: oid.OIDCountry, Value: "UA"},
		},
	}

	der, err := csr.Create(req, priv)
	require.NoError(t, err)
	require.NotEmpty(t, der)

	parsed, err := csr.Parse(der)
	require.NoError(t, err)
	require.NotNil(t, parsed.PublicKey)
}

// TestVerify checks that a freshly created CSR passes signature verification.
func TestVerify(t *testing.T) {
	priv, err := dstu4145.GenerateKey(ec.DSTU_PB_257())
	require.NoError(t, err)

	req := &csr.Request{
		Subject: []csr.AttributeTypeAndValue{
			{Type: oid.OIDCommonName, Value: "Verify Test"},
		},
	}

	der, err := csr.Create(req, priv)
	require.NoError(t, err)

	parsed, err := csr.Parse(der)
	require.NoError(t, err)

	require.NoError(t, parsed.Verify(), "Verify should pass on a fresh CSR")
}

// TestVerifyTampered checks that a tampered CSR fails verification.
func TestVerifyTampered(t *testing.T) {
	priv, err := dstu4145.GenerateKey(ec.DSTU_PB_257())
	require.NoError(t, err)

	req := &csr.Request{
		Subject: []csr.AttributeTypeAndValue{
			{Type: oid.OIDCommonName, Value: "Tamper Test"},
		},
	}

	der, err := csr.Create(req, priv)
	require.NoError(t, err)

	// Flip a byte in the middle of the DER.
	tampered := make([]byte, len(der))
	copy(tampered, der)
	tampered[len(tampered)/2] ^= 0xFF

	parsed, err := csr.Parse(tampered)
	if err != nil {
		// Acceptable: tamper may break ASN.1 parse.
		return
	}
	require.Error(t, parsed.Verify(), "Verify should fail on tampered CSR")
}

// TestEDRPOURoundtrip verifies Ukrainian EDRPOU attribute survives CSR round-trip.
func TestEDRPOURoundtrip(t *testing.T) {
	priv, err := dstu4145.GenerateKey(ec.DSTU_PB_257())
	require.NoError(t, err)

	edrpou := "12345678"
	req := &csr.Request{
		Subject: []csr.AttributeTypeAndValue{
			{Type: oid.OIDCommonName, Value: "EDRPOU Test"},
			{Type: oid.EDRPOU, Value: edrpou},
		},
	}

	der, err := csr.Create(req, priv)
	require.NoError(t, err)

	parsed, err := csr.Parse(der)
	require.NoError(t, err)

	// Find EDRPOU in parsed subject.
	found := false
	for _, a := range parsed.Subject {
		if a.Type.Equal(oid.EDRPOU) {
			require.Equal(t, edrpou, a.Value, "EDRPOU value mismatch")
			found = true
		}
	}
	require.True(t, found, "EDRPOU attribute not found in parsed CSR")
}

// TestDRFORoundtrip verifies Ukrainian DRFO attribute survives CSR round-trip.
func TestDRFORoundtrip(t *testing.T) {
	priv, err := dstu4145.GenerateKey(ec.DSTU_PB_257())
	require.NoError(t, err)

	drfo := "1234567890"
	req := &csr.Request{
		Subject: []csr.AttributeTypeAndValue{
			{Type: oid.OIDCommonName, Value: "DRFO Test"},
			{Type: oid.DRFO, Value: drfo},
		},
	}

	der, err := csr.Create(req, priv)
	require.NoError(t, err)

	parsed, err := csr.Parse(der)
	require.NoError(t, err)

	found := false
	for _, a := range parsed.Subject {
		if a.Type.Equal(oid.DRFO) {
			require.Equal(t, drfo, a.Value)
			found = true
		}
	}
	require.True(t, found, "DRFO attribute not found in parsed CSR")
}

// TestKupyna256SigAlg verifies CSR creation with explicit Kupyna-256 sig alg OID.
func TestKupyna256SigAlg(t *testing.T) {
	priv, err := dstu4145.GenerateKey(ec.DSTU_PB_257())
	require.NoError(t, err)

	req := &csr.Request{
		Subject: []csr.AttributeTypeAndValue{
			{Type: oid.OIDCommonName, Value: "Kupyna256 CSR"},
		},
		SignatureAlgorithmOID: asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 2},
	}

	der, err := csr.Create(req, priv)
	require.NoError(t, err)

	parsed, err := csr.Parse(der)
	require.NoError(t, err)
	require.NoError(t, parsed.Verify())
}
