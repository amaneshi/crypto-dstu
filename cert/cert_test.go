package cert

import (
	"crypto/rand"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"crypto-dstu/dstu4145"
	"crypto-dstu/ec"
	"crypto-dstu/oid"

	"github.com/stretchr/testify/require"
)

// ---- OID tests ----

func TestOIDConstants(t *testing.T) {
	require.Equal(t, "1.2.804.2.1.1.1.1.3.1.1", oid.DSTU4145WithGOST34311.String())
	require.Equal(t, "1.2.804.2.1.1.1.1.3.1.2", oid.DSTU4145WithKupyna256.String())
	require.Equal(t, "1.2.804.2.1.1.1.1.3.1.3", oid.DSTU4145WithKupyna512.String())
	require.Equal(t, "1.2.804.2.1.1.1.1.3.1.1.2.6", oid.CurvePB257.String())
}

func TestOIDCurveNameLookup(t *testing.T) {
	require.Equal(t, "DSTU_PB_257", oid.CurveNameByOID(oid.CurvePB257))
	require.Equal(t, "DSTU_PB_163", oid.CurveNameByOID(oid.CurvePB163))
	require.Equal(t, "DSTU_PB_431", oid.CurveNameByOID(oid.CurvePB431))
	require.Empty(t, oid.CurveNameByOID(asn1.ObjectIdentifier{9, 9, 9}))
}

func TestOIDAlgorithmName(t *testing.T) {
	require.Equal(t, "DSTU4145-with-GOST34311", oid.AlgorithmName(oid.DSTU4145WithGOST34311))
	require.Equal(t, "Kupyna-256", oid.AlgorithmName(oid.Kupyna256))
	unknown := asn1.ObjectIdentifier{9, 9, 9}
	require.Equal(t, unknown.String(), oid.AlgorithmName(unknown))
}

func TestOIDIsCurveOID(t *testing.T) {
	require.True(t, oid.IsCurveOID(oid.CurvePB257))
	require.True(t, oid.IsCurveOID(oid.CurvePB163))
	require.False(t, oid.IsCurveOID(oid.DSTU4145WithGOST34311))
	require.False(t, oid.IsCurveOID(asn1.ObjectIdentifier{9, 9, 9}))
}

func TestOIDIsDSTU4145SigAlg(t *testing.T) {
	require.True(t, oid.IsDSTU4145SigAlg(oid.DSTU4145WithGOST34311))
	require.True(t, oid.IsDSTU4145SigAlg(oid.DSTU4145WithKupyna256))
	require.True(t, oid.IsDSTU4145SigAlg(oid.DSTU4145WithKupyna512))
	require.False(t, oid.IsDSTU4145SigAlg(oid.CurvePB257))
}

// ---- Role detection tests ----

func TestDetectRolePersonal(t *testing.T) {
	c := &Certificate{DRFO: "1234567890"}
	require.Equal(t, RolePersonal, DetectRole(c))
}

func TestDetectRoleStamp(t *testing.T) {
	c := &Certificate{EDRPOU: "12345678"}
	require.Equal(t, RoleStamp, DetectRole(c))
}

func TestDetectRoleFOPEqual(t *testing.T) {
	c := &Certificate{DRFO: "1234567890", EDRPOU: "1234567890"}
	require.Equal(t, RoleFOP, DetectRole(c))
}

func TestDetectRoleFOPTenDigitEDRPOU(t *testing.T) {
	c := &Certificate{DRFO: "1234567890", EDRPOU: "9876543210"}
	require.Equal(t, RoleFOP, DetectRole(c))
}

func TestDetectRoleDirector(t *testing.T) {
	c := &Certificate{DRFO: "1234567890", EDRPOU: "12345678"}
	require.Equal(t, RoleDirector, DetectRole(c))
}

func TestDetectRoleOther(t *testing.T) {
	c := &Certificate{}
	require.Equal(t, RoleOther, DetectRole(c))
}

// ---- Certificate parsing tests ----

// bePadBytes zero-pads a big-endian byte slice to exactly n bytes by prepending zeros.
func bePadBytes(b []byte, n int) []byte {
	if len(b) >= n {
		return b[:n]
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// buildMinimalCert creates a minimal synthetic DER certificate for testing.
// It contains a TBS with version, serial, validity, subject, and a DSTU public key,
// then appends a dummy signature algorithm and signature.
func buildMinimalCert(
	t *testing.T,
	priv *dstu4145.PrivateKey,
	sigAlgOID asn1.ObjectIdentifier,
	subjectAttrs []any,
) []byte {
	t.Helper()

	curve := priv.Curve
	pub := priv.Public()

	// Encode public key as uncompressed LE X || LE Y (exact format expected by expandPublicKey).
	// We reverse each BE coordinate to LE and pad to byteLen to ensure exact round-trip.
	byteLen := (curve.M + 7) / 8
	xLE := leReverse(bePadBytes(pub.Q.X.Bytes(), byteLen))
	yLE := leReverse(bePadBytes(pub.Q.Y.Bytes(), byteLen))
	pkLE := make([]byte, len(xLE)+len(yLE))
	copy(pkLE, xLE)
	copy(pkLE[len(xLE):], yLE)

	// Find curve OID
	params := dstu4145.ParamsByName("DSTU_PB_257")
	if curve.M != 257 {
		// find correct params
		for _, p := range dstu4145.AllParams() {
			if p.Curve.M == curve.M {
				params = &p
				break
			}
		}
	}
	require.NotNil(t, params)

	spki, err := asn1.Marshal(struct {
		Algorithm struct {
			Algorithm asn1.ObjectIdentifier
		}
		PublicKey asn1.BitString
	}{
		Algorithm: struct{ Algorithm asn1.ObjectIdentifier }{params.OID},
		PublicKey: asn1.BitString{Bytes: pkLE, BitLength: len(pkLE) * 8},
	})
	require.NoError(t, err)

	// Build subject SEQUENCE
	subject := buildSubjectDER(t, subjectAttrs)

	now := time.Now().UTC().Truncate(time.Second)
	notAfter := now.Add(365 * 24 * time.Hour)

	tbs, err := asn1.Marshal(struct {
		Version       int `asn1:"optional,explicit,tag:0,default:0"`
		SerialNumber  *big.Int
		Signature     struct{ Algorithm asn1.ObjectIdentifier }
		Issuer        asn1.RawValue
		Validity      struct{ NotBefore, NotAfter time.Time }
		Subject       asn1.RawValue
		PublicKeyInfo asn1.RawValue
	}{
		Version:       2,
		SerialNumber:  big.NewInt(1),
		Signature:     struct{ Algorithm asn1.ObjectIdentifier }{sigAlgOID},
		Issuer:        asn1.RawValue{FullBytes: subject},
		Validity:      struct{ NotBefore, NotAfter time.Time }{now, notAfter},
		Subject:       asn1.RawValue{FullBytes: subject},
		PublicKeyInfo: asn1.RawValue{FullBytes: spki},
	})
	require.NoError(t, err)

	// Sign TBS
	sig, err := dstu4145.Sign(rand.Reader, priv, hashForAlg(t, tbs, sigAlgOID))
	require.NoError(t, err)
	sigDER, err := dstu4145.MarshalSignature(sig)
	require.NoError(t, err)

	cert, err := asn1.Marshal(struct {
		TBS       asn1.RawValue
		SigAlg    struct{ Algorithm asn1.ObjectIdentifier }
		Signature asn1.BitString
	}{
		TBS:       asn1.RawValue{FullBytes: tbs},
		SigAlg:    struct{ Algorithm asn1.ObjectIdentifier }{sigAlgOID},
		Signature: asn1.BitString{Bytes: sigDER, BitLength: len(sigDER) * 8},
	})
	require.NoError(t, err)
	return cert
}

// hashForAlg hashes data with the algorithm matching sigAlgOID.
func hashForAlg(t *testing.T, data []byte, sigAlgOID asn1.ObjectIdentifier) []byte {
	t.Helper()
	c := &Certificate{TBSRaw: data, SigAlgOID: sigAlgOID}
	digest, err := hashTBS(c)
	require.NoError(t, err)
	return digest
}

// buildSubjectDER builds a minimal SEQUENCE { SET { SEQUENCE { OID, UTF8String } } }.
func buildSubjectDER(t *testing.T, attrs []any) []byte {
	t.Helper()
	// attrs is pairs: [oid, value, oid, value, ...]
	type atv struct {
		Type  asn1.ObjectIdentifier
		Value string `asn1:"utf8"`
	}
	var sets [][]byte
	for i := 0; i+1 < len(attrs); i += 2 {
		o := attrs[i].(asn1.ObjectIdentifier)
		v := attrs[i+1].(string)
		atvDER, err := asn1.Marshal(atv{o, v})
		require.NoError(t, err)
		setDER, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      atvDER,
		})
		require.NoError(t, err)
		sets = append(sets, setDER)
	}
	var combined []byte
	for _, s := range sets {
		combined = append(combined, s...)
	}
	seq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      combined,
	})
	require.NoError(t, err)
	return seq
}

func TestParseCertificateBasic(t *testing.T) {
	priv, err := dstu4145.GenerateKey(ec.DSTU_PB_257())
	require.NoError(t, err)

	der := buildMinimalCert(t, priv, oid.DSTU4145WithGOST34311, []any{
		oid.OIDCommonName, "Test User",
	})

	c, err := ParseCertificate(der)
	require.NoError(t, err)
	require.NotNil(t, c)
	require.Equal(t, 3, c.Version) // version field 2 → Version 3
	require.Equal(t, big.NewInt(1), c.SerialNumber)
	require.True(t, c.SigAlgOID.Equal(oid.DSTU4145WithGOST34311))
	require.NotNil(t, c.PublicKey)
	require.Equal(t, "Test User", c.CommonName)
}

func TestParseCertificateUkrainianDN(t *testing.T) {
	priv, err := dstu4145.GenerateKey(ec.DSTU_PB_257())
	require.NoError(t, err)

	der := buildMinimalCert(t, priv, oid.DSTU4145WithGOST34311, []any{
		oid.OIDCommonName, "Іваненко Іван Іванович",
		oid.EDRPOU, "12345678",
		oid.DRFO, "1234567890",
		oid.OIDEmailAddress, "ivan@example.com",
	})

	c, err := ParseCertificate(der)
	require.NoError(t, err)
	require.Equal(t, "Іваненко Іван Іванович", c.CommonName)
	require.Equal(t, "12345678", c.EDRPOU)
	require.Equal(t, "1234567890", c.DRFO)
	require.Equal(t, "ivan@example.com", c.Email)
}

func TestParseCertificateTrailingData(t *testing.T) {
	priv, err := dstu4145.GenerateKey(ec.DSTU_PB_257())
	require.NoError(t, err)

	der := buildMinimalCert(t, priv, oid.DSTU4145WithGOST34311, nil)
	der = append(der, 0x00, 0x01) // append garbage

	_, err = ParseCertificate(der)
	require.Error(t, err)
}

func TestParseCertificateInvalidDER(t *testing.T) {
	_, err := ParseCertificate([]byte{0x30, 0x03, 0x01, 0x02, 0x03})
	require.Error(t, err)
}

// ---- Verify tests ----

func TestVerifyCertPKMatch(t *testing.T) {
	priv, err := dstu4145.GenerateKey(ec.DSTU_PB_257())
	require.NoError(t, err)

	der := buildMinimalCert(t, priv, oid.DSTU4145WithGOST34311, nil)
	c, err := ParseCertificate(der)
	require.NoError(t, err)

	require.NoError(t, VerifyCertPKMatch(c, priv))
}

func TestVerifyCertPKMatchWrongKey(t *testing.T) {
	priv, err := dstu4145.GenerateKey(ec.DSTU_PB_257())
	require.NoError(t, err)
	other, err := dstu4145.GenerateKey(ec.DSTU_PB_257())
	require.NoError(t, err)

	der := buildMinimalCert(t, priv, oid.DSTU4145WithGOST34311, nil)
	c, err := ParseCertificate(der)
	require.NoError(t, err)

	require.Error(t, VerifyCertPKMatch(c, other))
}

func TestVerifyCertSignature(t *testing.T) {
	priv, err := dstu4145.GenerateKey(ec.DSTU_PB_257())
	require.NoError(t, err)

	der := buildMinimalCert(t, priv, oid.DSTU4145WithGOST34311, nil)
	c, err := ParseCertificate(der)
	require.NoError(t, err)

	// Self-signed: issuer == subject, same key
	require.NoError(t, VerifyCert(c, c))
}

func TestVerifyCertChain(t *testing.T) {
	root, err := dstu4145.GenerateKey(ec.DSTU_PB_257())
	require.NoError(t, err)

	// Build a self-signed root cert; VerifyCertChain finds root by matching
	// root.Subject.Bytes == cert.Issuer.Bytes. A self-signed cert satisfies this.
	rootDER := buildMinimalCert(t, root, oid.DSTU4145WithGOST34311, []any{
		oid.OIDCommonName, "Test CA",
	})
	rootCert, err := ParseCertificate(rootDER)
	require.NoError(t, err)

	// Self-signed cert validates against itself as the root
	require.NoError(t, VerifyCertChain(rootCert, []*Certificate{rootCert}))
}

func TestVerifyCertChainNoRoot(t *testing.T) {
	priv, err := dstu4145.GenerateKey(ec.DSTU_PB_257())
	require.NoError(t, err)

	der := buildMinimalCert(t, priv, oid.DSTU4145WithGOST34311, nil)
	c, err := ParseCertificate(der)
	require.NoError(t, err)

	require.Error(t, VerifyCertChain(c, nil))
}

// ---- CertInfo tests ----

func TestGetCertInfo(t *testing.T) {
	priv, err := dstu4145.GenerateKey(ec.DSTU_PB_257())
	require.NoError(t, err)

	der := buildMinimalCert(t, priv, oid.DSTU4145WithGOST34311, []any{
		oid.OIDCommonName, "Test",
		oid.EDRPOU, "12345678",
		oid.DRFO, "1234567890",
	})

	ci, err := GetCertInfo(der)
	require.NoError(t, err)
	require.NotNil(t, ci)
	require.Equal(t, "Test", ci.CommonName)
	require.Equal(t, "12345678", ci.EDRPOU)
	require.Equal(t, "1234567890", ci.DRFO)
	require.Equal(t, "DSTU4145-with-GOST34311", ci.SigAlgOID)
	require.Equal(t, "DSTU_PB_257", ci.CurveOID)
	require.False(t, ci.NotBefore.IsZero())
	require.False(t, ci.NotAfter.IsZero())
}

func TestDetectRoleFromCert(t *testing.T) {
	tests := []struct {
		name     string
		drfo     string
		edrpou   string
		expected Role
	}{
		{"personal", "1234567890", "", RolePersonal},
		{"stamp", "", "12345678", RoleStamp},
		{"fop-equal", "1234567890", "1234567890", RoleFOP},
		{"fop-10digit", "1234567890", "9876543210", RoleFOP},
		{"director", "1234567890", "12345678", RoleDirector},
		{"other", "", "", RoleOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Certificate{DRFO: tt.drfo, EDRPOU: tt.edrpou}
			require.Equal(t, tt.expected, DetectRole(c))
		})
	}
}
