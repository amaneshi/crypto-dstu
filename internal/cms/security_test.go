package cms

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

func rewriteSignature(t *testing.T, der []byte, change func(*parsedSignedData)) []byte {
	t.Helper()
	inner, err := parseContentInfo(der, OIDSignedData)
	require.NoError(t, err)
	sd, err := parseSignedDataBytes(inner)
	require.NoError(t, err)
	change(sd)
	encoded, err := marshalSignedData(sd.Version, sd.DigestAlgorithms[0].Algorithm, EncapsulatedContentInfo{EContentType: sd.EContentType, EContent: sd.EContent}, sd.SignerInfos, sd.CertBytes)
	require.NoError(t, err)
	typ, err := asn1.Marshal(OIDSignedData)
	require.NoError(t, err)
	return marshalSEQ(append(typ, marshalEXPLICIT(0, encoded)...))
}

func TestVerificationRejectsAlteredContentAndSignature(t *testing.T) {
	key := mustGenerateKey(t)
	c := makeCert(t, key)
	content := []byte("authenticated document")
	raw, err := Sign(content, key, c, SignOptions{})
	require.NoError(t, err)
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"content", bytes.Replace(raw, content, []byte("unauthorized document!"), 1)},
		{"signature", rewriteSignature(t, raw, func(sd *parsedSignedData) { sd.SignerInfos[0].Signature[0] ^= 1 })},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := ParseSigned(tc.data)
			require.NoError(t, err)
			msg.Certificates = append(msg.Certificates, c)
			require.Error(t, VerifySigned(msg, nil, []*cert.Certificate{c}))
			require.False(t, msg.Signers[0].Valid)
			require.Error(t, msg.Signers[0].Error)
		})
	}
}

func TestDirectContentSignatureIsActuallyVerified(t *testing.T) {
	key := mustGenerateKey(t)
	c := makeCert(t, key)
	content := []byte("direct signature")
	raw, err := Sign(content, key, c, SignOptions{})
	require.NoError(t, err)
	direct := rewriteSignature(t, raw, func(sd *parsedSignedData) {
		si := &sd.SignerInfos[0]
		si.SignedAttrs = asn1.RawValue{}
		h := newHashForOID(si.DigestAlgorithm.Algorithm)
		h.Write(content)
		digest := h.Sum(nil)
		if isLEHashOID(si.DigestAlgorithm.Algorithm) {
			digest = reverseBytes(digest)
		}
		sig, err := dstu4145.Sign(rand.Reader, key, digest)
		require.NoError(t, err)
		si.Signature, err = dstu4145.MarshalSignatureRaw(sig, key.Curve)
		require.NoError(t, err)
	})
	msg, err := VerifySignedRaw(direct, nil, []*cert.Certificate{c})
	require.NoError(t, err)
	require.True(t, msg.Signers[0].Valid)
	fake := rewriteSignature(t, direct, func(sd *parsedSignedData) {
		sd.EContent = []byte("FORGED RECEIPT")
		sd.SignerInfos[0].Signature = []byte{0}
	})
	msg, err = VerifySignedRaw(fake, nil, []*cert.Certificate{c})
	require.Error(t, err)
	require.False(t, msg.Signers[0].Valid)
}

func TestEmptyAttachedContentIsNotDetached(t *testing.T) {
	k := mustGenerateKey(t)
	c := makeCert(t, k)
	raw, err := Sign(nil, k, c, SignOptions{})
	require.NoError(t, err)
	msg, err := VerifySignedRaw(raw, nil, []*cert.Certificate{c})
	require.NoError(t, err)
	require.NotNil(t, msg.Content)
	require.Empty(t, msg.Content)
}

func TestSigningCertificateBindingRejectsReplacement(t *testing.T) {
	key := mustGenerateKey(t)
	c := makeCert(t, key)
	raw, err := Sign([]byte("certificate-bound content"), key, c, SignOptions{})
	require.NoError(t, err)
	msg, err := ParseSigned(raw)
	require.NoError(t, err)
	replacement := *c
	replacement.Raw = append(append([]byte{}, c.Raw...), 0)
	msg.Certificates = []*cert.Certificate{&replacement}
	require.ErrorContains(t, VerifySigned(msg, nil, nil), "signing-certificate hash mismatch")
	require.False(t, msg.Signers[0].Valid)
}

func TestVerificationEnforcesTrustAndExpiry(t *testing.T) {
	key := mustGenerateKey(t)
	c := makeCert(t, key)
	raw, err := Sign([]byte("trusted"), key, c, SignOptions{})
	require.NoError(t, err)
	other := makeCert(t, mustGenerateKey(t))
	msg, err := ParseSigned(raw)
	require.NoError(t, err)
	msg.Certificates = append(msg.Certificates, c)
	require.Error(t, VerifySigned(msg, nil, []*cert.Certificate{other}))
	require.False(t, msg.Signers[0].Valid)
	require.NoError(t, VerifySigned(msg, nil, []*cert.Certificate{c}))
	require.True(t, msg.Signers[0].Valid)
	c.NotAfter = time.Now().Add(-time.Hour)
	require.Error(t, VerifySigned(msg, nil, []*cert.Certificate{c}))
	require.False(t, msg.Signers[0].Valid)
}

func TestUnknownAlgorithmsAndEmptySignersFail(t *testing.T) {
	key := mustGenerateKey(t)
	c := makeCert(t, key)
	raw, err := Sign([]byte("data"), key, c, SignOptions{})
	require.NoError(t, err)
	for _, tc := range []struct {
		name   string
		change func(*parsedSignedData)
	}{
		{"digest", func(sd *parsedSignedData) {
			sd.SignerInfos[0].DigestAlgorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3, 4}
		}},
		{"signature", func(sd *parsedSignedData) {
			sd.SignerInfos[0].SignatureAlgorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3, 4}
		}},
		{"no signers", func(sd *parsedSignedData) { sd.SignerInfos = nil }},
		{"duplicate attributes", func(sd *parsedSignedData) {
			attrs, err := BuildSignedAttrs(OIDData, []byte("digest"), time.Time{})
			require.NoError(t, err)
			attrs = append(attrs, attrs[0])
			sd.SignerInfos[0].SignedAttrs.FullBytes, err = MarshalSignedAttrs(attrs)
			require.NoError(t, err)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifySignedRaw(rewriteSignature(t, raw, tc.change), nil, []*cert.Certificate{c})
			require.Error(t, err)
		})
	}
}

func TestProducerUsesImplicitTagSortedAttributesAndRawSignature(t *testing.T) {
	key := mustGenerateKey(t)
	c := makeCert(t, key)
	for _, digest := range []asn1.ObjectIdentifier{oid.GOST34311, oid.Kupyna256, oid.Kupyna512} {
		t.Run(digest.String(), func(t *testing.T) {
			raw, err := Sign([]byte("profile"), key, c, SignOptions{DigestAlgorithm: digest})
			require.NoError(t, err)
			inner, err := parseContentInfo(raw, OIDSignedData)
			require.NoError(t, err)
			sd, err := parseSignedDataBytes(inner)
			require.NoError(t, err)
			si := sd.SignerInfos[0]
			require.Equal(t, byte(0xa0), si.SignedAttrs.FullBytes[0])
			require.Len(t, si.Signature, 2*((new(big.Int).SetBytes(key.Curve.N).BitLen()+7)/8))
			var attrs asn1.RawValue
			_, err = asn1.Unmarshal(si.SignedAttrs.FullBytes, &attrs)
			require.NoError(t, err)
			var previous []byte
			remaining := attrs.Bytes
			for len(remaining) > 0 {
				var attr asn1.RawValue
				remaining, err = asn1.Unmarshal(remaining, &attr)
				require.NoError(t, err)
				require.LessOrEqual(t, bytes.Compare(previous, attr.FullBytes), 0)
				previous = attr.FullBytes
			}
			msg, err := VerifySignedRaw(raw, nil, []*cert.Certificate{c})
			require.NoError(t, err)
			require.True(t, msg.Signers[0].Valid)
		})
	}
}
