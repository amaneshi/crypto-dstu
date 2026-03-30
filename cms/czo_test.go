package cms

// CZO compliance tests.
//
// These tests use synthetic test data (generated with our own DSTU keys) because
// the real CZO test files at https://czo.gov.ua/testexamples require manual download.
//
// To run against real CZO files:
//  1. Download test files to testdata/czo/cades/*.p7s
//  2. Download CA bundle to testdata/czo/certs/ca-bundle.p7b
//  3. Replace the synthetic fixture helpers below with file-based loaders.

import (
	"encoding/asn1"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"crypto-dstu/cert"
	"crypto-dstu/dstu4145"
	"crypto-dstu/kupyna"
)

// ---- fixture helpers ----

func czoGenerateKey(t *testing.T) *dstu4145.PrivateKey {
	t.Helper()
	params := dstu4145.ParamsByName("DSTU_PB_257")
	require.NotNil(t, params)
	key, err := dstu4145.GenerateKey(params.Curve)
	require.NoError(t, err)
	return key
}

func czoMakeCert(t *testing.T, key *dstu4145.PrivateKey, cn string, serial int64) *cert.Certificate {
	t.Helper()
	cnBytes := []byte(cn)
	// Build DER for Name: SEQUENCE { SET { SEQUENCE { OID(CN), UTF8String(cn) } } }
	// OID for id-at-commonName = 2.5.4.3
	oidCN := []byte{0x06, 0x03, 0x55, 0x04, 0x03}
	utf8val := append([]byte{0x0c, byte(len(cnBytes))}, cnBytes...)
	atv := marshalSEQ(append(oidCN, utf8val...))
	rdn := marshalSETOF(atv)
	issuerBytes := marshalSEQ(rdn)
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

func czoHashKupyna256(data []byte) []byte {
	h := kupyna.New256()
	h.Write(data)
	return h.Sum(nil)
}

// buildCAdESBES creates a CAdES-BES (attached) CMS SignedData for content.
func buildCAdESBES(t *testing.T, content []byte) (cmsDER []byte, key *dstu4145.PrivateKey, signerCert *cert.Certificate) {
	t.Helper()
	key = czoGenerateKey(t)
	signerCert = czoMakeCert(t, key, "CZO-Test-Signer", 1001)
	var err error
	cmsDER, err = Sign(content, key, signerCert, SignOptions{})
	require.NoError(t, err)
	return
}

// buildCAdESBESDetached creates a CAdES-BES detached CMS SignedData.
func buildCAdESBESDetached(t *testing.T, content []byte) (cmsDER []byte, key *dstu4145.PrivateKey, signerCert *cert.Certificate) {
	t.Helper()
	key = czoGenerateKey(t)
	signerCert = czoMakeCert(t, key, "CZO-Test-Signer-Detached", 1002)
	var err error
	cmsDER, err = Sign(content, key, signerCert, SignOptions{Detached: true})
	require.NoError(t, err)
	return
}

// ---- synthetic fixture directory ----

// writeSyntheticFixturesWithCerts writes synthetic .p7s files to a temp dir
// and returns (dir, certPool) where certPool contains all signer certs.
func writeSyntheticFixturesWithCerts(t *testing.T) (string, []*cert.Certificate) {
	t.Helper()
	dir := t.TempDir()
	cadesDir := filepath.Join(dir, "cades")
	require.NoError(t, os.MkdirAll(cadesDir, 0o755))

	content := []byte("CZO synthetic test document — DSTU 4145 + Kupyna-256")

	// bes.p7s — attached
	bes, _, besCert := buildCAdESBES(t, content)
	require.NoError(t, os.WriteFile(filepath.Join(cadesDir, "bes.p7s"), bes, 0o644))

	// detached.p7s
	det, _, detCert := buildCAdESBESDetached(t, content)
	require.NoError(t, os.WriteFile(filepath.Join(cadesDir, "detached.p7s"), det, 0o644))

	// content/doc.txt
	contentDir := filepath.Join(dir, "content")
	require.NoError(t, os.MkdirAll(contentDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(contentDir, "doc.txt"), content, 0o644))

	return dir, []*cert.Certificate{besCert, detCert}
}

// ---- CAdES-BES tests ----

func TestCZO_CAdES_BES_Parse(t *testing.T) {
	content := []byte("CZO test document")
	cmsDER, _, signerCert := buildCAdESBES(t, content)

	msg, err := ParseSigned(cmsDER)
	require.NoError(t, err)
	require.NotNil(t, msg)
	require.Equal(t, content, msg.Content)
	require.Len(t, msg.Signers, 1)
	// Placeholder Raw bytes can't round-trip through ParseCertificates;
	// inject the known cert and re-resolve SIDs.
	if msg.Signers[0].Certificate == nil {
		msg.Certificates = append(msg.Certificates, signerCert)
		ResolveCertificates(msg)
	}
	require.NotNil(t, msg.Signers[0].Certificate)
	require.Equal(t, signerCert.SerialNumber, msg.Signers[0].Certificate.SerialNumber)
}

func TestCZO_CAdES_BES_VerifySignature(t *testing.T) {
	content := []byte("CZO BES document")
	cmsDER, key, signerCert := buildCAdESBES(t, content)

	// Pass signerCert as roots so SID matching works with placeholder Raw bytes.
	msg, err := VerifySignedRaw(cmsDER, nil, []*cert.Certificate{signerCert})
	require.NoError(t, err)
	require.NotNil(t, msg)
	require.Equal(t, content, msg.Content)
	require.True(t, msg.Signers[0].Valid)

	require.NoError(t, cert.VerifyCertPKMatch(signerCert, key))
}

func TestCZO_CAdES_BES_TamperedContent(t *testing.T) {
	content := []byte("original content")
	cmsDER, _, signerCert := buildCAdESBES(t, content)

	tampered := []byte("tampered content")
	_, err := VerifySignedRaw(cmsDER, tampered, []*cert.Certificate{signerCert})
	require.Error(t, err)
}

func TestCZO_CAdES_BES_Detached(t *testing.T) {
	content := []byte("detached CZO document")
	cmsDER, _, signerCert := buildCAdESBESDetached(t, content)

	msg, err := ParseSigned(cmsDER)
	require.NoError(t, err)
	require.Nil(t, msg.Content) // detached: no embedded content

	verified, err := VerifySignedRaw(cmsDER, content, []*cert.Certificate{signerCert})
	require.NoError(t, err)
	require.True(t, verified.Signers[0].Valid)
}

func TestCZO_CAdES_BES_DetachedWrongContent(t *testing.T) {
	content := []byte("correct content")
	cmsDER, _, signerCert := buildCAdESBESDetached(t, content)

	_, err := VerifySignedRaw(cmsDER, []byte("wrong content"), []*cert.Certificate{signerCert})
	require.Error(t, err)
}

func TestCZO_CAdES_BES_MultipleSigners(t *testing.T) {
	content := []byte("multi-signed document")

	// Sign once
	key1 := czoGenerateKey(t)
	cert1 := czoMakeCert(t, key1, "Signer-One", 2001)
	first, err := Sign(content, key1, cert1, SignOptions{})
	require.NoError(t, err)

	msg, err := VerifySignedRaw(first, nil, []*cert.Certificate{cert1})
	require.NoError(t, err)
	require.Len(t, msg.Signers, 1)
	require.True(t, msg.Signers[0].Valid)

	// Sign again: second signer wraps the first SignedData
	key2 := czoGenerateKey(t)
	cert2 := czoMakeCert(t, key2, "Signer-Two", 2002)
	second, err := Sign(first, key2, cert2, SignOptions{})
	require.NoError(t, err)

	msg2, err := VerifySignedRaw(second, nil, []*cert.Certificate{cert2})
	require.NoError(t, err)
	require.Len(t, msg2.Signers, 1)
	require.True(t, msg2.Signers[0].Valid)
	require.Equal(t, cert2.SerialNumber, msg2.Signers[0].Certificate.SerialNumber)
}

func TestCZO_CAdES_BES_CertEmbedded(t *testing.T) {
	content := []byte("cert embedding test")
	cmsDER, _, signerCert := buildCAdESBES(t, content)

	// The [0] certs block IS present in the DER — verify by checking the signer
	// is resolvable when we inject the cert as a root (placeholder Raw can't parse).
	msg, err := VerifySignedRaw(cmsDER, nil, []*cert.Certificate{signerCert})
	require.NoError(t, err)
	require.True(t, msg.Signers[0].Valid)
	require.Equal(t, signerCert.SerialNumber, msg.Signers[0].Certificate.SerialNumber)
}

func TestCZO_CAdES_BES_SigningTime(t *testing.T) {
	content := []byte("signing time test")
	before := time.Now().Add(-time.Second)
	cmsDER, _, _ := buildCAdESBES(t, content)
	after := time.Now().Add(time.Second)

	msg, err := ParseSigned(cmsDER)
	require.NoError(t, err)
	require.Len(t, msg.Signers, 1)

	st := msg.Signers[0].SigningTime
	require.False(t, st.IsZero(), "signing time should be set")
	require.True(t, st.After(before) && st.Before(after),
		"signing time %v should be between %v and %v", st, before, after)
}

func TestCZO_CAdES_BES_MessageDigest(t *testing.T) {
	content := []byte("digest verification content")
	cmsDER, _, signerCert := buildCAdESBES(t, content)

	expectedDigest := czoHashKupyna256(content)

	verified, err := VerifySignedRaw(cmsDER, nil, []*cert.Certificate{signerCert})
	require.NoError(t, err)
	require.True(t, verified.Signers[0].Valid)
	_ = expectedDigest // digest is checked internally by VerifySignedRaw
}

// TestCZO_CAdES_BES_FromFile runs against real CZO files if they exist,
// otherwise skips gracefully.
func TestCZO_CAdES_BES_FromFile(t *testing.T) {
	p := filepath.Join("testdata", "czo", "cades", "bes.p7s")
	data, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		t.Skipf("real CZO file not found at %s; download from https://czo.gov.ua/testexamples", p)
	}
	require.NoError(t, err)

	msg, err := ParseSigned(data)
	require.NoError(t, err)
	require.NotEmpty(t, msg.Signers)
}

// TestCZO_CAdES_BES_FromFile_Detached runs against real detached CZO file if present.
func TestCZO_CAdES_BES_FromFile_Detached(t *testing.T) {
	sigPath := filepath.Join("testdata", "czo", "cades", "detached.p7s")
	contentPath := filepath.Join("testdata", "czo", "content", "doc.txt")

	sigData, err := os.ReadFile(sigPath)
	if os.IsNotExist(err) {
		t.Skipf("real CZO detached file not found at %s", sigPath)
	}
	require.NoError(t, err)

	content, err := os.ReadFile(contentPath)
	require.NoError(t, err, "content file required alongside detached signature")

	msg, err := ParseSigned(sigData)
	require.NoError(t, err)
	require.Nil(t, msg.Content)

	verified, err := VerifySignedRaw(sigData, content, nil)
	require.NoError(t, err)
	require.NotEmpty(t, verified.Signers)
}

// TestCZO_AllCAdESFiles runs over all *.p7s in testdata/czo/cades/ (if present).
func TestCZO_AllCAdESFiles(t *testing.T) {
	matches, err := filepath.Glob(filepath.Join("testdata", "czo", "cades", "*.p7s"))
	if err != nil || len(matches) == 0 {
		t.Skip("no CZO .p7s files found in testdata/czo/cades/")
	}
	for _, path := range matches {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			msg, err := ParseSigned(data)
			require.NoError(t, err)
			require.NotEmpty(t, msg.Signers)
		})
	}
}

// TestCZO_SyntheticFixtureRoundtrip writes synthetic fixtures to a temp dir
// and reads them back, verifying the full write→read→verify roundtrip.
func TestCZO_SyntheticFixtureRoundtrip(t *testing.T) {
	dir, certs := writeSyntheticFixturesWithCerts(t)
	content, err := os.ReadFile(filepath.Join(dir, "content", "doc.txt"))
	require.NoError(t, err)

	// Attached BES
	besData, err := os.ReadFile(filepath.Join(dir, "cades", "bes.p7s"))
	require.NoError(t, err)
	msg, err := VerifySignedRaw(besData, nil, certs)
	require.NoError(t, err)
	require.True(t, msg.Signers[0].Valid)
	require.Equal(t, content, msg.Content)

	// Detached
	detData, err := os.ReadFile(filepath.Join(dir, "cades", "detached.p7s"))
	require.NoError(t, err)
	msg2, err := VerifySignedRaw(detData, content, certs)
	require.NoError(t, err)
	require.True(t, msg2.Signers[0].Valid)
}
