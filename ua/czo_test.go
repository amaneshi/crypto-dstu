package ua

// CZO end-to-end compliance tests using the high-level Box API.
//
// Real CZO test files are downloaded automatically from https://czo.gov.ua/testexamples
// by TestMain. No manual steps required.

import (
	"encoding/asn1"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"crypto-dstu/internal/cert"
	"crypto-dstu/pkg/dstu4145"
	czo "crypto-dstu/testdata/czo"
)

func TestMain(m *testing.M) {
	if err := czo.EnsureFiles(); err != nil {
		panic("czo: failed to download test fixtures: " + err.Error())
	}
	os.Exit(m.Run())
}

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
	inner := make([]byte, len(oidCN)+len(utf8val))
	copy(inner, oidCN)
	copy(inner[len(oidCN):], utf8val)
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

func czoBox(t *testing.T) (*Box, *cert.Certificate) {
	t.Helper()
	key := czoKey(t)
	c := czoCert(t, key, "CZO-Test-UA", 5001)
	b := NewBox()
	b.keys = []*keyEntry{{
		privateKey: key,
		signCert:   c,
		cryptCert:  c,
		role:       cert.RolePersonal,
	}}
	return b, c
}

// ---- Box lifecycle ----

func TestCZO_BoxLoadCABundleInvalid(t *testing.T) {
	b := NewBox()
	err := b.LoadCABundle([]byte{0x00, 0x01, 0x02})
	require.Error(t, err)
	require.Empty(t, b.caCerts)
}

func TestCZO_BoxAddTSPAndKeyByRole(t *testing.T) {
	b, _ := czoBox(t)
	b.AddTSP("http://tsp.czo.gov.ua/")
	require.Len(t, b.tspClients, 1)
	require.Equal(t, "http://tsp.czo.gov.ua/", b.tspClients[0].URL)

	i := b.KeyByRole("personal")
	require.Equal(t, 0, i)
}

// ---- SignDocument / UnsignDocument (CAdES-BES style) ----

func TestCZO_SignUnsign_Attached(t *testing.T) {
	b, _ := czoBox(t)
	content := []byte("<Document>CZO test</Document>")

	signed, err := b.SignDocument(content, SignOptions{NoTax: true})
	require.NoError(t, err)
	require.NotEmpty(t, signed)

	result, err := b.UnsignDocument(signed)
	require.NoError(t, err)
	require.Equal(t, content, result.Content)
	require.Len(t, result.Signers, 1)
	require.NotNil(t, result.Signers[0].CertInfo)
	require.False(t, result.Signers[0].SigningTime.IsZero())
}

func TestCZO_SignUnsign_TransportContainer(t *testing.T) {
	b, _ := czoBox(t)
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
	b, _ := czoBox(t)
	content := []byte("detached CZO document content")

	signed, err := b.SignDocument(content, SignOptions{NoTax: true, Detached: true})
	require.NoError(t, err)

	result, err := b.UnsignDocument(signed)
	require.NoError(t, err)
	require.Nil(t, result.Content)
	require.Len(t, result.Signers, 1)
	require.NotNil(t, result.Signers[0].CertInfo)
}

func TestCZO_SignUnsign_CertInfo(t *testing.T) {
	b, _ := czoBox(t)
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
	b, _ := czoBox(t)
	_, err := b.UnsignDocument([]byte{0x00, 0x01, 0x02})
	require.Error(t, err)
}

// ---- Encrypt / Decrypt ----

func TestCZO_EncryptDecrypt(t *testing.T) {
	b, c := czoBox(t)
	content := []byte("confidential CZO document")

	enc, err := b.encryptDocument(content, c)
	require.NoError(t, err)

	dec, err := b.DecryptDocument(enc)
	require.NoError(t, err)
	require.Equal(t, content, dec)
}

func TestCZO_DecryptWrongKey(t *testing.T) {
	b1, c1 := czoBox(t)
	b2, _ := czoBox(t)

	enc, err := b1.encryptDocument([]byte("secret"), c1)
	require.NoError(t, err)

	// b2 has a different key — decryption should fail
	_, err = b2.DecryptDocument(enc)
	require.Error(t, err)
}

// ---- Sign + Encrypt full roundtrip ----

func TestCZO_SignAndEncrypt_Roundtrip(t *testing.T) {
	b, c := czoBox(t)
	content := []byte("<xml>Signed and encrypted tax document</xml>")

	container, err := b.signAndEncryptWithCert(content, c, SignOptions{
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
	require.NotNil(t, result.Signers[0].CertInfo)
}

func TestCZO_SignAndEncrypt_NoTax(t *testing.T) {
	b, c := czoBox(t)
	content := []byte("raw sign+encrypt")

	der, err := b.signAndEncryptWithCert(content, c, SignOptions{NoTax: true})
	require.NoError(t, err)

	plain, err := b.DecryptDocument(der)
	require.NoError(t, err)

	result, err := b.UnsignDocument(plain)
	require.NoError(t, err)
	require.Equal(t, content, result.Content)
}

func TestCZO_SignAndEncrypt_ContainerStructure(t *testing.T) {
	b, c := czoBox(t)
	content := []byte("container structure test")

	raw, err := b.signAndEncryptWithCert(content, c, SignOptions{Filename: "doc.xml"})
	require.NoError(t, err)

	// Header is surfaced via UnsignResult after decrypt+unsign roundtrip
	signed, err := b.DecryptDocument(raw)
	require.NoError(t, err)
	result, err := b.UnsignDocument(signed)
	require.NoError(t, err)
	require.Equal(t, content, result.Content)
	require.NotNil(t, result.Signers[0].CertInfo)
}

// ---- GetCertInfo ----

func TestCZO_GetCertInfo(t *testing.T) {
	key := czoKey(t)
	c := czoCert(t, key, "UA-Signer", 7001)
	info := certInfoFromCert(c)
	require.NotNil(t, info)
	require.NotEmpty(t, info.Serial)
	require.Equal(t, string(cert.RoleOther), info.Role)
	require.False(t, info.NotBefore.IsZero())
	require.False(t, info.NotAfter.IsZero())
}

// ---- CMS-level verification via Box CACerts ----

func TestCZO_VerifyWithCACerts(t *testing.T) {
	b, signerCert := czoBox(t)

	// Add signer cert as "trusted CA" so chain verification passes
	b.caCerts = append(b.caCerts, signerCert)

	content := []byte("verified with CA pool")
	signed, err := b.SignDocument(content, SignOptions{NoTax: true})
	require.NoError(t, err)

	result, err := b.UnsignDocument(signed)
	require.NoError(t, err)
	require.Equal(t, content, result.Content)
	require.NotNil(t, result.Signers[0].CertInfo)
}

// ---- Real CZO file tests (auto-downloaded by TestMain) ----

func TestCZO_Real_Box_DSTU_BES_Enveloped(t *testing.T) {
	data, err := os.ReadFile(czo.Path("cades/DSTU/enveloped/CAdES-BES/test.txt.p7s"))
	require.NoError(t, err)

	b := NewBox()
	result, err := b.UnsignDocument(data)
	require.NoError(t, err)
	require.NotEmpty(t, result.Signers)
	require.NotNil(t, result.Content)
}

func TestCZO_Real_Box_DSTU_BES_Detached(t *testing.T) {
	sigData, err := os.ReadFile(czo.Path("cades/DSTU/detached/CAdES-BES/test.txt.p7s"))
	require.NoError(t, err)

	b := NewBox()
	if certData, e := os.ReadFile(czo.Path("certs/DSTU/DSTU_sign.cer")); e == nil {
		_ = b.AddCert(certData)
	}
	result, err := b.UnsignDocument(sigData)
	require.NoError(t, err)
	require.NotEmpty(t, result.Signers)
	require.Nil(t, result.Content) // detached: no embedded content
}

func TestCZO_Real_Box_DSTU_T_Enveloped(t *testing.T) {
	data, err := os.ReadFile(czo.Path("cades/DSTU/enveloped/CAdES-T/test.txt.p7s"))
	require.NoError(t, err)

	b := NewBox()
	result, err := b.UnsignDocument(data)
	require.NoError(t, err)
	require.NotEmpty(t, result.Signers)
}

func TestCZO_Real_Box_DSTU7564_BES_Enveloped(t *testing.T) {
	data, err := os.ReadFile(czo.Path("cades/DSTU-7564/enveloped/CAdES-BES/test.txt.p7s"))
	require.NoError(t, err)

	b := NewBox()
	result, err := b.UnsignDocument(data)
	require.NoError(t, err)
	require.NotEmpty(t, result.Signers)
	require.NotNil(t, result.Content)
}

func TestCZO_Real_Box_LoadSignerCert(t *testing.T) {
	b := NewBox()
	err := b.AddCertFile(czo.Path("certs/DSTU/DSTU_sign.cer"))
	require.NoError(t, err)
	require.Len(t, b.caCerts, 1)
	require.NotNil(t, b.caCerts[0].PublicKey)
}

func TestCZO_Real_Box_AllFormats_DSTU(t *testing.T) {
	formats := []string{"CAdES-BES", "CAdES-T", "CAdES-C", "CAdES-X_Long"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			data, err := os.ReadFile(czo.Path("cades/DSTU/enveloped/" + format + "/test.txt.p7s"))
			require.NoError(t, err)
			b := NewBox()
			result, err := b.UnsignDocument(data)
			require.NoError(t, err)
			require.NotEmpty(t, result.Signers)
		})
	}
}
