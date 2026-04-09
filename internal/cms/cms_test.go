package cms

import (
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"crypto-dstu/internal/cert"
	"crypto-dstu/pkg/dstu4145"
)

// ---- helpers ----

func mustGenerateKey(t *testing.T) *dstu4145.PrivateKey {
	t.Helper()
	params := dstu4145.ParamsByName("DSTU_PB_257")
	require.NotNil(t, params)
	key, err := dstu4145.GenerateKey(params.Curve)
	require.NoError(t, err)
	return key
}

// makeCert builds a minimal *cert.Certificate from a key (no real DER, fields only).
// The issuer is a simple SEQUENCE { SET { SEQUENCE { OID, "Test" } } } DER blob.
func makeCert(t *testing.T, key *dstu4145.PrivateKey) *cert.Certificate {
	t.Helper()
	// Build a minimal RDN: SEQUENCE { SET { SEQUENCE { OID(cn), UTF8String("TestUser") } } }
	// "TestUser" = 8 bytes; inner SEQ = OID(5) + UTF8(10) = 15; SET = 17; outer SEQ = 19
	issuerBytes := []byte{
		0x30, 0x13, // SEQUENCE length=19
		0x31, 0x11, // SET length=17
		0x30, 0x0f, // SEQUENCE length=15
		0x06, 0x03, 0x55, 0x04, 0x03, // OID 2.5.4.3 (commonName)
		0x0c, 0x08, 0x54, 0x65, 0x73, 0x74, 0x55, 0x73, 0x65, 0x72, // UTF8 "TestUser" (8 bytes)
	}
	issuer := asn1.RawValue{FullBytes: issuerBytes}

	return &cert.Certificate{
		Raw:          []byte{0x30, 0x03, 0x01, 0x02, 0x03}, // placeholder
		SerialNumber: big.NewInt(42),
		Issuer:       issuer,
		Subject:      issuer,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		PublicKey:    key.Public(),
	}
}

// ---- CMS attribute tests ----

func TestBuildSignedAttrs(t *testing.T) {
	digest := []byte("fakedigest32bytesxxxxxxxxxxxxxx12")
	now := time.Now().UTC().Truncate(time.Second)
	attrs, err := BuildSignedAttrs(OIDData, digest, now)
	require.NoError(t, err)
	require.Len(t, attrs, 3) // contentType, messageDigest, signingTime
	require.Equal(t, OIDContentType, attrs[0].Type)
	require.Equal(t, OIDMessageDigest, attrs[1].Type)
	require.Equal(t, OIDSigningTime, attrs[2].Type)
}

func TestBuildSignedAttrsNoTime(t *testing.T) {
	attrs, err := BuildSignedAttrs(OIDData, []byte("digest"), time.Time{})
	require.NoError(t, err)
	require.Len(t, attrs, 2) // no signingTime
}

func TestMarshalSignedAttrs(t *testing.T) {
	attrs, err := BuildSignedAttrs(OIDData, []byte("somedigest"), time.Now())
	require.NoError(t, err)
	der, err := MarshalSignedAttrs(attrs)
	require.NoError(t, err)
	require.NotEmpty(t, der)
	// Must start with SET OF tag (0x31)
	require.Equal(t, byte(0x31), der[0])
}

func TestFindAttribute(t *testing.T) {
	attrs, err := BuildSignedAttrs(OIDData, []byte("d"), time.Now())
	require.NoError(t, err)
	found := FindAttribute(attrs, OIDMessageDigest)
	require.NotNil(t, found)
	require.Nil(t, FindAttribute(attrs, OIDTimestampToken))
}

// ---- OID constants ----

func TestOIDConstants(t *testing.T) {
	require.Equal(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}, OIDData)
	require.Equal(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}, OIDSignedData)
	require.Equal(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}, OIDEnvelopedData)
	require.Equal(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}, OIDMessageDigest)
	require.Equal(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}, OIDSigningTime)
}

// ---- SignedData roundtrip ----

func TestSignRoundtrip(t *testing.T) {
	key := mustGenerateKey(t)
	c := makeCert(t, key)
	content := []byte("Hello, Ukrainian PKI!")

	der, err := Sign(content, key, c, SignOptions{})
	require.NoError(t, err)
	require.NotEmpty(t, der)

	// Must parse as ContentInfo with OIDSignedData
	var ci ContentInfo
	_, err = asn1.Unmarshal(der, &ci)
	require.NoError(t, err)
	require.True(t, ci.ContentType.Equal(OIDSignedData))
}

func TestSignDetached(t *testing.T) {
	key := mustGenerateKey(t)
	c := makeCert(t, key)
	content := []byte("Detached content")

	der, err := Sign(content, key, c, SignOptions{Detached: true})
	require.NoError(t, err)
	require.NotEmpty(t, der)

	var ci ContentInfo
	_, err = asn1.Unmarshal(der, &ci)
	require.NoError(t, err)
	require.True(t, ci.ContentType.Equal(OIDSignedData))
}

func TestSignVerifyRoundtrip(t *testing.T) {
	key := mustGenerateKey(t)
	c := makeCert(t, key)
	content := []byte("Test document content for signing")

	der, err := Sign(content, key, c, SignOptions{})
	require.NoError(t, err)

	msg, err := VerifySignedRaw(der, nil, []*cert.Certificate{c})
	require.NoError(t, err)
	require.Equal(t, content, msg.Content)
	require.Len(t, msg.Signers, 1)
	require.True(t, msg.Signers[0].Valid, "signature must be valid, error: %v", msg.Signers[0].Error)
}

func TestSignVerifyDetached(t *testing.T) {
	key := mustGenerateKey(t)
	c := makeCert(t, key)
	content := []byte("Detached document")

	der, err := Sign(content, key, c, SignOptions{Detached: true})
	require.NoError(t, err)

	msg, err := VerifySignedRaw(der, content, []*cert.Certificate{c})
	require.NoError(t, err)
	require.Len(t, msg.Signers, 1)
	require.True(t, msg.Signers[0].Valid, "signature must be valid, error: %v", msg.Signers[0].Error)
}

func TestSignVerifyTamperedContent(t *testing.T) {
	key := mustGenerateKey(t)
	c := makeCert(t, key)
	content := []byte("Original content")

	der, err := Sign(content, key, c, SignOptions{Detached: true})
	require.NoError(t, err)

	tampered := []byte("Tampered content!")
	_, err = VerifySignedRaw(der, tampered, []*cert.Certificate{c})
	require.Error(t, err)
}

func TestParseSigned(t *testing.T) {
	key := mustGenerateKey(t)
	c := makeCert(t, key)
	content := []byte("parse me")

	der, err := Sign(content, key, c, SignOptions{})
	require.NoError(t, err)

	msg, err := ParseSigned(der)
	require.NoError(t, err)
	require.Equal(t, content, msg.Content)
	require.Len(t, msg.Signers, 1)
}

func TestParseSignedInvalidDER(t *testing.T) {
	_, err := ParseSigned([]byte{0x00, 0x01, 0x02})
	require.Error(t, err)
}

func TestSignCustomContentType(t *testing.T) {
	key := mustGenerateKey(t)
	c := makeCert(t, key)
	content := []byte("XML document")
	xmlOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 25, 5}

	der, err := Sign(content, key, c, SignOptions{ContentType: xmlOID})
	require.NoError(t, err)

	msg, err := VerifySignedRaw(der, nil, []*cert.Certificate{c})
	require.NoError(t, err)
	require.True(t, msg.Signers[0].Valid)
}

func TestSigningTimeExtracted(t *testing.T) {
	key := mustGenerateKey(t)
	c := makeCert(t, key)
	content := []byte("timed content")

	der, err := Sign(content, key, c, SignOptions{})
	require.NoError(t, err)

	msg, err := ParseSigned(der)
	require.NoError(t, err)
	require.Len(t, msg.Signers, 1)
	// Signing time should be close to now
	require.False(t, msg.Signers[0].SigningTime.IsZero())
	require.WithinDuration(t, time.Now(), msg.Signers[0].SigningTime, 10*time.Second)
}

// ---- EnvelopedData roundtrip ----

func TestEncryptDecryptRoundtrip(t *testing.T) {
	senderKey := mustGenerateKey(t)
	recipKey := mustGenerateKey(t)
	recipCert := makeCert(t, recipKey)

	plaintext := []byte("Secret document for tax office")

	der, err := Encrypt(plaintext, []*cert.Certificate{recipCert}, senderKey)
	require.NoError(t, err)
	require.NotEmpty(t, der)

	// Parse
	msg, err := ParseEnveloped(der)
	require.NoError(t, err)
	require.NotEmpty(t, msg.CipherText)
	require.Len(t, msg.IV, 8)

	// Decrypt
	recovered, err := DecryptEnveloped(msg, recipKey, recipCert)
	require.NoError(t, err)
	require.Equal(t, plaintext, recovered)
}

func TestEncryptNoRecipients(t *testing.T) {
	senderKey := mustGenerateKey(t)
	_, err := Encrypt([]byte("data"), nil, senderKey)
	require.Error(t, err)
}

func TestParseEnvelopedInvalidDER(t *testing.T) {
	_, err := ParseEnveloped([]byte{0x01, 0x02})
	require.Error(t, err)
}

func TestParseEnvelopedWrongContentType(t *testing.T) {
	// Build a ContentInfo with wrong OID
	ci := ContentInfo{
		ContentType: OIDData, // wrong
		Content:     asn1.RawValue{FullBytes: []byte{0x04, 0x02, 0x01, 0x02}},
	}
	der, err := asn1.Marshal(ci)
	require.NoError(t, err)
	_, err = ParseEnveloped(der)
	require.Error(t, err)
}

func TestEncryptDecryptWrongKey(t *testing.T) {
	senderKey := mustGenerateKey(t)
	recipKey := mustGenerateKey(t)
	wrongKey := mustGenerateKey(t) // different key
	recipCert := makeCert(t, recipKey)

	der, err := Encrypt([]byte("secret"), []*cert.Certificate{recipCert}, senderKey)
	require.NoError(t, err)

	msg, err := ParseEnveloped(der)
	require.NoError(t, err)

	// wrongKey has different serial — no matching recipient
	wrongCert := makeCert(t, wrongKey)
	wrongCert.SerialNumber = big.NewInt(999)
	_, err = DecryptEnveloped(msg, wrongKey, wrongCert)
	require.Error(t, err)
}

// ---- CRC32 / TLV helpers ----

func TestTLVShortLength(t *testing.T) {
	content := []byte{0xAA, 0xBB}
	encoded := tlv(0x04, content)
	require.Equal(t, []byte{0x04, 0x02, 0xAA, 0xBB}, encoded)
}

func TestTLVLongLength(t *testing.T) {
	content := make([]byte, 200)
	encoded := tlv(0x04, content)
	require.Equal(t, byte(0x04), encoded[0])
	require.Equal(t, byte(0x81), encoded[1]) // long form: 1 byte length
	require.Equal(t, byte(200), encoded[2])
}

// ---- ec.Curve.Words availability check ----

func TestECCurveWords(t *testing.T) {
	params := dstu4145.ParamsByName("DSTU_PB_257")
	require.NotNil(t, params)
	require.Equal(t, 9, params.Curve.Words) // ceil(257/32) = 9
}

// ---- rebuildPubFromBEXY ----

func TestRebuildPubFromBEXY(t *testing.T) {
	key := mustGenerateKey(t)
	pub := key.Public()
	curve := key.Curve
	byteLen := (curve.M + 7) / 8

	xBytes := make([]byte, byteLen)
	yBytes := make([]byte, byteLen)
	xRaw := pub.Q.X.Bytes()
	yRaw := pub.Q.Y.Bytes()
	copy(xBytes[byteLen-len(xRaw):], xRaw)
	copy(yBytes[byteLen-len(yRaw):], yRaw)

	rebuilt, err := rebuildPubFromBEXY(curve, xBytes, yBytes)
	require.NoError(t, err)
	require.True(t, rebuilt.Q.X.Equal(pub.Q.X))
	require.True(t, rebuilt.Q.Y.Equal(pub.Q.Y))
}
