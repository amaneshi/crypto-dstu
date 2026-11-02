package ocsp_test

import (
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"crypto-dstu/internal/cert"
	"crypto-dstu/internal/ocsp"
	"crypto-dstu/internal/oid"
	"crypto-dstu/pkg/dstu4145"
	"crypto-dstu/pkg/ec"
	"crypto-dstu/pkg/gost34311"
)

// syntheticCert builds a minimal cert.Certificate for testing.
func syntheticCert(t *testing.T) *cert.Certificate {
	t.Helper()
	priv, err := dstu4145.GenerateKey(ec.DSTU_PB_257())
	require.NoError(t, err)
	pub := priv.Public()
	keyBytes, err := asn1.Marshal(pub.Q.Compress())
	require.NoError(t, err)

	subjectRaw, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes: func() []byte {
			b, _ := asn1.Marshal(struct {
				T asn1.ObjectIdentifier
				V string `asn1:"utf8"`
			}{T: oid.OIDCommonName, V: "Test"})
			s, _ := asn1.Marshal(asn1.RawValue{
				Class: asn1.ClassUniversal, Tag: asn1.TagSet,
				IsCompound: true, Bytes: b,
			})
			return s
		}(),
	})
	require.NoError(t, err)

	return &cert.Certificate{
		SerialNumber:          big.NewInt(12345),
		Subject:               asn1.RawValue{FullBytes: subjectRaw},
		Issuer:                asn1.RawValue{FullBytes: subjectRaw},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		PublicKey:             pub,
		SubjectPublicKeyBytes: keyBytes,
		SigAlgOID:             oid.DSTU4145WithGOST34311,
	}
}

// TestNewCertID verifies CertID construction with Kupyna-256.
func TestNewCertID(t *testing.T) {
	subject := syntheticCert(t)
	issuer := syntheticCert(t)

	cid, err := ocsp.NewCertID(subject, issuer, oid.Kupyna256)
	require.NoError(t, err)
	require.NotNil(t, cid)
	require.Equal(t, oid.Kupyna256, cid.HashAlgorithmOID)
	require.Len(t, cid.IssuerNameHash, 32, "Kupyna-256 output is 32 bytes")
	require.Equal(t, subject.SerialNumber, cid.SerialNumber)
}

// TestNewCertIDGOST34311 verifies CertID construction with GOST 34.311.
func TestNewCertIDGOST34311(t *testing.T) {
	subject := syntheticCert(t)
	issuer := syntheticCert(t)

	cid, err := ocsp.NewCertID(subject, issuer, oid.GOST34311)
	require.NoError(t, err)
	require.Len(t, cid.IssuerNameHash, gost34311.Size)
}

// TestNewCertIDUnsupportedHash verifies error on unknown hash OID.
func TestNewCertIDUnsupportedHash(t *testing.T) {
	subject := syntheticCert(t)
	issuer := syntheticCert(t)
	badOID := asn1.ObjectIdentifier{1, 2, 3, 4}

	_, err := ocsp.NewCertID(subject, issuer, badOID)
	require.Error(t, err)
}

// TestRequestMarshal verifies that Request.Marshal produces valid ASN.1.
func TestRequestMarshal(t *testing.T) {
	subject := syntheticCert(t)
	issuer := syntheticCert(t)

	cid, err := ocsp.NewCertID(subject, issuer, oid.Kupyna256)
	require.NoError(t, err)

	req, err := ocsp.NewRequest([]*ocsp.CertID{cid})
	require.NoError(t, err)

	der, err := req.Marshal()
	require.NoError(t, err)
	require.NotEmpty(t, der)

	// Verify it's valid DER: must start with SEQUENCE tag 0x30.
	require.Equal(t, byte(0x30), der[0], "DER should start with SEQUENCE tag")
}

// TestRequestMarshalMultiple verifies marshalling multiple CertIDs.
func TestRequestMarshalMultiple(t *testing.T) {
	subject := syntheticCert(t)
	issuer := syntheticCert(t)

	cid1, err := ocsp.NewCertID(subject, issuer, oid.Kupyna256)
	require.NoError(t, err)
	cid2, err := ocsp.NewCertID(issuer, issuer, oid.GOST34311)
	require.NoError(t, err)

	req, err := ocsp.NewRequest([]*ocsp.CertID{cid1, cid2})
	require.NoError(t, err)

	der, err := req.Marshal()
	require.NoError(t, err)
	require.NotEmpty(t, der)
}

// TestAIAOCSPURLs verifies URL extraction from AIA extension.
func TestAIAOCSPURLs(t *testing.T) {
	c := &cert.Certificate{}
	// No AIA → empty result.
	urls := ocsp.AIAOCSPURLs(c)
	require.Empty(t, urls)
}

// TestNewRequestEmpty verifies that an empty CertID list returns an error.
func TestNewRequestEmpty(t *testing.T) {
	_, err := ocsp.NewRequest(nil)
	require.Error(t, err)
}

// TestParseResponseInvalid verifies that garbage DER returns an error.
func TestParseResponseInvalid(t *testing.T) {
	_, err := ocsp.ParseResponse([]byte{0x00, 0x01, 0x02})
	require.Error(t, err)
}

// TestClientHTTPMock verifies the HTTP client posts to a mock server
// and returns whatever the mock returns (error on bad body here).
func TestClientHTTPMock(t *testing.T) {
	// Serve a minimal "unsuccessful" OCSP response (status = 6 = unauthorized).
	// OCSPResponseStatus ::= ENUMERATED { successful(0), ... unauthorized(6) }
	// DER for ENUMERATED(6): 0a 01 06
	// OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED }
	der, err := asn1.Marshal(struct {
		Status asn1.Enumerated
	}{Status: 6})
	require.NoError(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(der)
	}))
	defer ts.Close()

	subject := syntheticCert(t)
	issuer := syntheticCert(t)

	client := &ocsp.Client{
		HTTP: ts.Client(),
		URL:  ts.URL,
	}
	resp, err := client.Check(subject, issuer)
	require.NoError(t, err)
	require.Equal(t, 6, resp.Status)
}
