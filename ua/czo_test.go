package ua

// CZO end-to-end compliance tests using the high-level Box API.
//
// Tests use synthetic data (generated with our own DSTU keys) because
// real CZO test files require manual download from https://czo.gov.ua/testexamples.
//
// To run against real CZO files, place them under testdata/czo/ and the
// "FromFile" tests below will pick them up automatically.

import (
	"encoding/asn1"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"crypto-dstu/cert"
	"crypto-dstu/cms"
	"crypto-dstu/dstu4145"
	"crypto-dstu/transport"
)

// ---- fixture helpers ----

func czoKey(t *testing.T) *dstu4145.PrivateKey {
	t.Helper()
	params := dstu4145.ParamsByName("DSTU_PB_257")
	require.NotNil(t, params)
	key, err := dstu4145.GenerateKey(params.Curve)
	require.NoError(t, err)
	return key
}

func czoCert(t *testing.T, key *dstu4145.PrivateKey, cn string, serial int64) *cert.Certificate {
	t.Helper()
	cnBytes := []byte(cn)
	oidCN := []byte{0x06, 0x03, 0x55, 0x04, 0x03}
	utf8val := append([]byte{0x0c, byte(len(cnBytes))}, cnBytes...)
	inner := append(oidCN, utf8val...)
	atv := append([]byte{0x30, byte(len(inner))}, inner...)
	rdn := append([]byte{0x31, byte(len(atv))}, atv...)
	issuerBytes := append([]byte{0x30, byte(len(rdn))}, rdn...)
	issuer := asn1.RawValue{FullBytes: issuerBytes}
	return &cert.Certificate{
		Raw:          []byte{0x30, 0x03, 0x01, 0x02, 0x03},
		SerialNumber: big.NewInt(serial),
		Issuer:       issuer,
		Subject:      issuer,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		PublicKey:    key.Public(),
	}
}

func czoBox(t *testing.T) (*Box, *dstu4145.PrivateKey, *cert.Certificate) {
	t.Helper()
	key := czoKey(t)
	c := czoCert(t, key, "CZO-Test-UA", 5001)
	b := NewBox()
	b.Keys = []*KeyEntry{{
		PrivateKey: key,
		SignCert:   c,
		CryptCert:  c,
		Role:       cert.RolePersonal,
	}}
	return b, key, c
}

// ---- Box lifecycle ----

func TestCZO_BoxLoadCABundleInvalid(t *testing.T) {
	b := NewBox()
	err := b.LoadCABundle([]byte{0x00, 0x01, 0x02})
	require.Error(t, err)
	require.Empty(t, b.CACerts)
}

func TestCZO_BoxAddTSPAndKeyByRole(t *testing.T) {
	b, _, _ := czoBox(t)
	b.AddTSP("http://tsp.czo.gov.ua/")
	require.Len(t, b.TSPClients, 1)
	require.Equal(t, "http://tsp.czo.gov.ua/", b.TSPClients[0].URL)

	e := b.KeyByRole(cert.RolePersonal)
	require.NotNil(t, e)
}

// ---- SignDocument / UnsignDocument (CAdES-BES style) ----

func TestCZO_SignUnsign_Attached(t *testing.T) {
	b, _, _ := czoBox(t)
	content := []byte("<Document>CZO test</Document>")

	signed, err := b.SignDocument(content, SignOptions{NoTax: true})
	require.NoError(t, err)
	require.NotEmpty(t, signed)

	result, err := b.UnsignDocument(signed)
	require.NoError(t, err)
	require.Equal(t, content, result.Content)
	require.Len(t, result.Signers, 1)
	require.NotNil(t, result.Signers[0].Certificate)
	require.NotNil(t, result.Signers[0].CertInfo)
	require.False(t, result.Signers[0].SigningTime.IsZero())
}

func TestCZO_SignUnsign_TransportContainer(t *testing.T) {
	b, _, _ := czoBox(t)
	content := []byte("<xml>UA Tax Document</xml>")

	signed, err := b.SignDocument(content, SignOptions{
		Filename: "taxdoc.xml",
		Email:    "user@example.com",
	})
	require.NoError(t, err)

	result, err := b.UnsignDocument(signed)
	require.NoError(t, err)
	require.Equal(t, content, result.Content)
	require.NotNil(t, result.Header)
	require.Equal(t, "taxdoc.xml", result.Header.Filename)
	require.Equal(t, "user@example.com", result.Header.SndEmail)
}

func TestCZO_SignUnsign_Detached(t *testing.T) {
	b, _, _ := czoBox(t)
	content := []byte("detached CZO document content")

	signed, err := b.SignDocument(content, SignOptions{NoTax: true, Detached: true})
	require.NoError(t, err)

	result, err := b.UnsignDocument(signed)
	require.NoError(t, err)
	require.Nil(t, result.Content)
	require.Len(t, result.Signers, 1)
	require.NotNil(t, result.Signers[0].Certificate)
}

func TestCZO_SignUnsign_CertInfo(t *testing.T) {
	b, _, _ := czoBox(t)
	content := []byte("cert info test")

	signed, err := b.SignDocument(content, SignOptions{NoTax: true})
	require.NoError(t, err)

	result, err := b.UnsignDocument(signed)
	require.NoError(t, err)
	require.Len(t, result.Signers, 1)

	info := result.Signers[0].CertInfo
	require.NotNil(t, info)
	require.NotEmpty(t, info.Serial)
	require.False(t, info.NotBefore.IsZero())
	require.False(t, info.NotAfter.IsZero())
}

func TestCZO_SignUnsign_InvalidDER(t *testing.T) {
	b, _, _ := czoBox(t)
	_, err := b.UnsignDocument([]byte{0x00, 0x01, 0x02})
	require.Error(t, err)
}

// ---- Encrypt / Decrypt ----

func TestCZO_EncryptDecrypt(t *testing.T) {
	b, _, c := czoBox(t)
	content := []byte("confidential CZO document")

	enc, err := b.EncryptDocument(content, c)
	require.NoError(t, err)

	dec, err := b.DecryptDocument(enc)
	require.NoError(t, err)
	require.Equal(t, content, dec)
}

func TestCZO_DecryptWrongKey(t *testing.T) {
	b1, _, c1 := czoBox(t)
	b2, _, _ := czoBox(t)

	enc, err := b1.EncryptDocument([]byte("secret"), c1)
	require.NoError(t, err)

	// b2 has a different key — decryption should fail
	_, err = b2.DecryptDocument(enc)
	require.Error(t, err)
}

// ---- Sign + Encrypt full roundtrip ----

func TestCZO_SignAndEncrypt_Roundtrip(t *testing.T) {
	b, _, c := czoBox(t)
	content := []byte("<xml>Signed and encrypted tax document</xml>")

	container, err := b.SignAndEncrypt(content, c, SignOptions{
		Filename: "enc-taxdoc.xml",
	})
	require.NoError(t, err)
	require.NotEmpty(t, container)

	// Decrypt crypt section
	signedDER, err := b.DecryptDocument(container)
	require.NoError(t, err)

	// Unsign to recover original content
	result, err := b.UnsignDocument(signedDER)
	require.NoError(t, err)
	require.Equal(t, content, result.Content)
	require.NotNil(t, result.Signers[0].Certificate)
}

func TestCZO_SignAndEncrypt_NoTax(t *testing.T) {
	b, _, c := czoBox(t)
	content := []byte("raw sign+encrypt")

	der, err := b.SignAndEncrypt(content, c, SignOptions{NoTax: true})
	require.NoError(t, err)

	plain, err := b.DecryptDocument(der)
	require.NoError(t, err)

	result, err := b.UnsignDocument(plain)
	require.NoError(t, err)
	require.Equal(t, content, result.Content)
}

func TestCZO_SignAndEncrypt_ContainerStructure(t *testing.T) {
	b, _, c := czoBox(t)
	content := []byte("container structure test")

	raw, err := b.SignAndEncrypt(content, c, SignOptions{Filename: "doc.xml"})
	require.NoError(t, err)

	container, err := transport.Decode(raw)
	require.NoError(t, err)
	require.NotNil(t, container.Header)
	require.Equal(t, "doc.xml", container.Header.Filename)

	signSection := container.FindSection("UA1_SIGN")
	require.NotNil(t, signSection)

	cryptSection := container.FindSection("UA1_CRYPT")
	require.NotNil(t, cryptSection)
}

// ---- GetCertInfo ----

func TestCZO_GetCertInfo(t *testing.T) {
	key := czoKey(t)
	c := czoCert(t, key, "UA-Signer", 7001)
	info := certInfoFromCert(c)
	require.NotNil(t, info)
	require.NotEmpty(t, info.Serial)
	require.Equal(t, cert.RoleOther, info.Role)
	require.False(t, info.NotBefore.IsZero())
	require.False(t, info.NotAfter.IsZero())
}

// ---- CMS-level verification via Box CACerts ----

func TestCZO_VerifyWithCACerts(t *testing.T) {
	b, _, signerCert := czoBox(t)

	// Add signer cert as "trusted CA" so chain verification passes
	b.CACerts = append(b.CACerts, signerCert)

	content := []byte("verified with CA pool")
	signed, err := b.SignDocument(content, SignOptions{NoTax: true})
	require.NoError(t, err)

	result, err := b.UnsignDocument(signed)
	require.NoError(t, err)
	require.Equal(t, content, result.Content)
	require.NotNil(t, result.Signers[0].Certificate)
}

// ---- File-based tests (skip if files absent) ----

func TestCZO_FromFile_BES(t *testing.T) {
	p := filepath.Join("..", "testdata", "czo", "cades", "bes.p7s")
	data, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		t.Skipf("real CZO BES file not found at %s; download from https://czo.gov.ua/testexamples", p)
	}
	require.NoError(t, err)

	b := NewBox()
	result, err := b.UnsignDocument(data)
	require.NoError(t, err)
	require.NotEmpty(t, result.Signers)
}

func TestCZO_FromFile_Detached(t *testing.T) {
	sigPath := filepath.Join("..", "testdata", "czo", "cades", "detached.p7s")
	contentPath := filepath.Join("..", "testdata", "czo", "content", "doc.txt")

	sigData, err := os.ReadFile(sigPath)
	if os.IsNotExist(err) {
		t.Skipf("real CZO detached file not found at %s", sigPath)
	}
	require.NoError(t, err)

	content, err := os.ReadFile(contentPath)
	require.NoError(t, err, "content file required alongside detached signature")

	msg, err := cms.ParseSigned(sigData)
	require.NoError(t, err)
	require.Nil(t, msg.Content)

	verified, err := cms.VerifySignedRaw(sigData, content, nil)
	require.NoError(t, err)
	require.NotEmpty(t, verified.Signers)
}

func TestCZO_AllCAdESFiles(t *testing.T) {
	matches, _ := filepath.Glob(filepath.Join("..", "testdata", "czo", "cades", "*.p7s"))
	if len(matches) == 0 {
		t.Skip("no CZO .p7s files found in testdata/czo/cades/")
	}
	b := NewBox()
	for _, path := range matches {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			result, err := b.UnsignDocument(data)
			require.NoError(t, err)
			require.NotEmpty(t, result.Signers)
		})
	}
}
