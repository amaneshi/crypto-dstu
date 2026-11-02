package ua

import (
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
)

// ---- test helpers ----

func mustGenerateKey(t *testing.T) *dstu4145.PrivateKey {
	t.Helper()
	params := dstu4145.ParamsByName("DSTU_PB_257")
	require.NotNil(t, params)
	key, err := dstu4145.GenerateKey(params.Curve)
	require.NoError(t, err)
	return key
}

func makeCert(t *testing.T, key *dstu4145.PrivateKey) *cert.Certificate {
	t.Helper()
	issuerBytes := []byte{
		0x30, 0x13,
		0x31, 0x11,
		0x30, 0x0f,
		0x06, 0x03, 0x55, 0x04, 0x03,
		0x0c, 0x08, 0x54, 0x65, 0x73, 0x74, 0x55, 0x73, 0x65, 0x72, // "TestUser"
	}
	issuer := asn1.RawValue{FullBytes: issuerBytes}
	return &cert.Certificate{
		Raw:          []byte{0x30, 0x03, 0x01, 0x02, 0x03},
		SerialNumber: big.NewInt(42),
		Issuer:       issuer,
		Subject:      issuer,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		PublicKey:    key.Public(),
	}
}

func makeBox(t *testing.T) (*Box, *cert.Certificate) {
	t.Helper()
	key := mustGenerateKey(t)
	c := makeCert(t, key)
	b := NewBox()
	b.keys = []*keyEntry{{
		privateKey: key,
		signCert:   c,
		cryptCert:  c,
		role:       cert.RolePersonal,
	}}
	b.caCerts = []*cert.Certificate{c} // Explicit test certificate pin.
	return b, c
}

// ---- Box tests ----

func TestNewBox(t *testing.T) {
	b := NewBox()
	require.NotNil(t, b)
	require.Empty(t, b.keys)
	require.Empty(t, b.caCerts)
	require.Empty(t, b.tspClients)
}

func TestBoxAddTSP(t *testing.T) {
	b := NewBox()
	b.AddTSP("http://tsp.example.com/")
	require.Len(t, b.tspClients, 1)
	require.Equal(t, "http://tsp.example.com/", b.tspClients[0].URL)
}

func TestBoxFirstKeyEmpty(t *testing.T) {
	b := NewBox()
	_, err := b.firstKey()
	require.Error(t, err)
}

func TestBoxKeyByRole(t *testing.T) {
	b, _ := makeBox(t)
	i := b.KeyByRole("personal")
	require.Equal(t, 0, i)

	i2 := b.KeyByRole("director")
	require.Equal(t, -1, i2)
}

func TestBoxAddCert(t *testing.T) {
	b := NewBox()
	key := mustGenerateKey(t)
	c := makeCert(t, key)
	err := b.AddCert(c.Raw)
	// Raw is placeholder bytes {0x30 0x03 0x01 0x02 0x03} — parse will fail
	require.Error(t, err) // expected: placeholder cert is not valid DER
}

// ---- SignDocument / UnsignDocument ----

func TestSignDocumentRawCMS(t *testing.T) {
	b, _ := makeBox(t)
	content := []byte("Hello, Ukraine!")

	der, err := b.SignDocument(content, SignOptions{NoTax: true})
	require.NoError(t, err)
	require.NotEmpty(t, der)

	// Should be parseable as CMS
	result, err := b.UnsignDocument(der)
	require.NoError(t, err)
	require.Equal(t, content, result.Content)
	require.Len(t, result.Signers, 1)
	// The stub cert has no chain — signature math verifies, chain check fails without roots
	require.NotNil(t, result.Signers[0].CertInfo)
}

func TestSignDocumentTransportContainer(t *testing.T) {
	b, _ := makeBox(t)
	content := []byte("<xml>data</xml>")

	der, err := b.SignDocument(content, SignOptions{
		Filename: "doc.xml",
		Email:    "test@example.com",
	})
	require.NoError(t, err)
	require.NotEmpty(t, der)

	result, err := b.UnsignDocument(der)
	require.NoError(t, err)
	require.Equal(t, content, result.Content)
	require.NotNil(t, result.Header)
	require.Equal(t, "doc.xml", result.Header.Filename)
}

func TestSignDocumentDetached(t *testing.T) {
	b, _ := makeBox(t)
	content := []byte("detached content")

	der, err := b.SignDocument(content, SignOptions{NoTax: true, Detached: true})
	require.NoError(t, err)

	// Detached: content is NOT embedded — UnsignDocument will return nil Content
	result, err := b.UnsignDocumentWithContent(der, content)
	require.NoError(t, err)
	require.Equal(t, content, result.Content) // detached: no embedded content
	require.Len(t, result.Signers, 1)
}

func TestSignDocumentNoKey(t *testing.T) {
	b := NewBox()
	_, err := b.SignDocument([]byte("data"), SignOptions{NoTax: true})
	require.Error(t, err)
}

func TestUnsignDocumentRawCMS(t *testing.T) {
	b, _ := makeBox(t)
	content := []byte("test document")

	signedDER, err := b.SignDocument(content, SignOptions{NoTax: true})
	require.NoError(t, err)

	result, err := b.UnsignDocument(signedDER)
	require.NoError(t, err)
	require.Equal(t, content, result.Content)
	require.NotNil(t, result.Signers[0].CertInfo)
}

func TestUnsignDocumentInvalidDER(t *testing.T) {
	b, _ := makeBox(t)
	_, err := b.UnsignDocument([]byte{0x00, 0x01, 0x02})
	require.Error(t, err)
}

// ---- EncryptDocument / DecryptDocument ----

func TestEncryptDecryptRoundtrip(t *testing.T) {
	b, c := makeBox(t)
	content := []byte("secret message")

	encDER, err := b.encryptDocument(content, c)
	require.NoError(t, err)
	require.NotEmpty(t, encDER)

	plaintext, err := b.DecryptDocument(encDER)
	require.NoError(t, err)
	require.Equal(t, content, plaintext)
}

func TestEncryptDocumentNoKey(t *testing.T) {
	b := NewBox()
	_, err := b.EncryptDocument([]byte("data"), []byte{0x30, 0x00})
	require.Error(t, err)
}

func TestDecryptDocumentNoKey(t *testing.T) {
	b := NewBox()
	_, err := b.DecryptDocument([]byte{0x30, 0x00})
	require.Error(t, err)
}

// ---- SignAndEncrypt / DecryptDocument + UnsignDocument ----

func TestSignAndEncryptRoundtrip(t *testing.T) {
	b, c := makeBox(t)
	content := []byte("sign and encrypt me")

	container, err := b.signAndEncryptWithCert(content, c, SignOptions{Filename: "enc.xml"})
	require.NoError(t, err)
	require.NotEmpty(t, container)

	// Decrypt the crypt section
	plainSigned, err := b.DecryptDocument(container)
	require.NoError(t, err)

	// Unsign to get original content
	result, err := b.UnsignDocument(plainSigned)
	require.NoError(t, err)
	require.Equal(t, content, result.Content)
	require.NotNil(t, result.Signers[0].CertInfo)
}

func TestSignAndEncryptNoTax(t *testing.T) {
	b, c := makeBox(t)
	content := []byte("raw sign+encrypt")

	der, err := b.signAndEncryptWithCert(content, c, SignOptions{NoTax: true})
	require.NoError(t, err)
	require.NotEmpty(t, der)

	// The result is raw CMS EnvelopedData
	plainSigned, err := b.DecryptDocument(der)
	require.NoError(t, err)

	result, err := b.UnsignDocument(plainSigned)
	require.NoError(t, err)
	require.Equal(t, content, result.Content)
}

// ---- GetCertInfo ----

func TestGetCertInfoInvalidDER(t *testing.T) {
	_, err := GetCertInfo([]byte{0x00, 0x01})
	require.Error(t, err)
}

func TestCertInfoFromCert(t *testing.T) {
	key := mustGenerateKey(t)
	c := makeCert(t, key)
	info := certInfoFromCert(c)
	require.NotNil(t, info)
	require.Equal(t, string(cert.RoleOther), info.Role) // stub cert has no DRFO/EDRPOU → "other"
	require.False(t, info.IsCA)
}

// ---- VerifyCert ----

func TestVerifyCertExpired(t *testing.T) {
	b := NewBox()
	key := mustGenerateKey(t)
	issuerBytes := []byte{
		0x30, 0x13, 0x31, 0x11, 0x30, 0x0f,
		0x06, 0x03, 0x55, 0x04, 0x03,
		0x0c, 0x08, 0x54, 0x65, 0x73, 0x74, 0x55, 0x73, 0x65, 0x72,
	}
	expired := &cert.Certificate{
		Raw:          []byte{0x30, 0x03, 0x01, 0x02, 0x03},
		SerialNumber: big.NewInt(1),
		Issuer:       asn1.RawValue{FullBytes: issuerBytes},
		Subject:      asn1.RawValue{FullBytes: issuerBytes},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     time.Now().Add(-time.Hour), // already expired
		PublicKey:    key.Public(),
	}
	// VerifyCert expects real DER; use the cert package directly
	err := cert.VerifyCert(expired, expired)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expired")
	_ = b
}
