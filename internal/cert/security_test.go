package cert

import (
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"testing"
	"time"

	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/amaneshi/crypto-dstu/pkg/ec"
	"github.com/stretchr/testify/require"
)

func securityCert(t *testing.T) (*Certificate, *dstu4145.PrivateKey) {
	t.Helper()
	k, err := dstu4145.GenerateKey(ec.DSTU_PB_257())
	require.NoError(t, err)
	c, err := ParseCertificate(buildMinimalCert(t, k, oid.DSTU4145WithKupyna256, []any{oid.OIDCommonName, "test"}))
	require.NoError(t, err)
	return c, k
}

func TestTrustRequiresExplicitMatchingAnchor(t *testing.T) {
	c, k := securityCert(t)
	other, _ := securityCert(t)
	require.NoError(t, VerifyCertPKMatch(c, k))
	require.NoError(t, VerifyCertChain(c, []*Certificate{c}))
	require.Error(t, VerifyCertChain(c, nil))
	require.Error(t, VerifyCertChain(c, []*Certificate{other}))
	c.NotAfter = time.Now().Add(-time.Hour)
	require.Error(t, VerifyCertChain(c, []*Certificate{c}))
}

func TestKeyMatchRejectsOppositePointWithSameX(t *testing.T) {
	c, k := securityCert(t)
	c.PublicKey = &dstu4145.PublicKey{Curve: k.Curve, Q: k.Public().Q.Neg()}
	require.True(t, c.PublicKey.Q.X.Equal(k.Public().Q.X))
	require.Error(t, VerifyCertPKMatch(c, k))
}

func issueSecurityCert(t *testing.T, c, issuer *Certificate, key *dstu4145.PrivateKey, exts []rawExtension) *Certificate {
	t.Helper()
	var tbs tbsCertificate
	_, err := asn1.Unmarshal(c.TBSRaw, &tbs)
	require.NoError(t, err)
	tbs.Raw = nil
	tbs.Issuer = issuer.Subject
	tbs.Extensions = exts
	raw, err := asn1.Marshal(tbs)
	require.NoError(t, err)
	sig, err := dstu4145.Sign(rand.Reader, key, hashForAlg(t, raw, c.SigAlgOID))
	require.NoError(t, err)
	sigDER, err := dstu4145.MarshalSignature(sig)
	require.NoError(t, err)
	der, err := asn1.Marshal(outerCertificate{TBSCertificate: asn1.RawValue{FullBytes: raw}, SignatureAlgorithm: algorithmIdentifier{Algorithm: c.SigAlgOID}, Signature: asn1.BitString{Bytes: sigDER, BitLength: len(sigDER) * 8}})
	require.NoError(t, err)
	result, err := ParseCertificate(der)
	require.NoError(t, err)
	return result
}

func TestChainUsesDiscoveryOnlyToReachExplicitRoot(t *testing.T) {
	root, rootKey := securityCert(t)
	intermediate, intermediateKey := securityCert(t)
	leaf, _ := securityCert(t)
	constraints := func(path int) []rawExtension {
		bc, err := asn1.Marshal(struct {
			CA      bool
			MaxPath int
		}{true, path})
		require.NoError(t, err)
		ku, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x04}, BitLength: 6})
		require.NoError(t, err)
		return []rawExtension{{Id: oid.OIDExtBasicConstraints, Critical: true, Value: bc}, {Id: oid.OIDExtKeyUsage, Critical: true, Value: ku}}
	}
	root = issueSecurityCert(t, root, root, rootKey, constraints(1))
	intermediate = issueSecurityCert(t, intermediate, root, rootKey, constraints(0))
	leaf = issueSecurityCert(t, leaf, intermediate, intermediateKey, nil)
	roots := []*Certificate{root}
	discovery := []*Certificate{intermediate}
	require.NoError(t, VerifyCertChainWithIntermediates(leaf, roots, discovery))
	require.Error(t, VerifyCertChainWithIntermediates(leaf, nil, append(discovery, root)))
	require.Error(t, VerifyCertChainWithIntermediates(leaf, roots, nil))
	intermediate.Extensions = nil
	require.Error(t, VerifyCertChainWithIntermediates(leaf, roots, discovery))
}

func TestCertificatePolicyRejectsWrongUsageAndUnknownCriticalExtension(t *testing.T) {
	c, _ := securityCert(t)
	usage, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x08}, BitLength: 5})
	require.NoError(t, err)
	c.Extensions = []Extension{{Id: oid.OIDExtKeyUsage, Critical: true, Value: usage}}
	require.Error(t, CheckSigningUsage(c))
	require.NoError(t, CheckEncryptionUsage(c))
	require.Error(t, issuerPolicy(c, 0))
	bc, err := asn1.Marshal(struct {
		CA      bool
		MaxPath int
	}{true, 0})
	require.NoError(t, err)
	c.Extensions = []Extension{{Id: oid.OIDExtBasicConstraints, Critical: true, Value: bc}}
	require.NoError(t, issuerPolicy(c, 0))
	require.Error(t, issuerPolicy(c, 1))
	c.Extensions = append(c.Extensions, Extension{Id: asn1.ObjectIdentifier{1, 2, 3, 99}, Critical: true})
	require.Error(t, VerifyCertChain(c, []*Certificate{c}))
}

func TestCertificateBundlesParseEveryCertificate(t *testing.T) {
	a, _ := securityCert(t)
	b, _ := securityCert(t)
	concatenated := append(append([]byte{}, a.Raw...), b.Raw...)
	pemBytes := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.Raw}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.Raw})...)
	// Independently encode a certs-only PKCS#7 SignedData bundle.
	dataOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	signedOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	sd, err := asn1.Marshal(struct {
		Version      int
		Digests      []asn1.RawValue `asn1:"set"`
		Content      struct{ Type asn1.ObjectIdentifier }
		Certificates asn1.RawValue
		Signers      []asn1.RawValue `asn1:"set"`
	}{Version: 1, Content: struct{ Type asn1.ObjectIdentifier }{dataOID}, Certificates: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: concatenated}})
	require.NoError(t, err)
	p7b, err := asn1.Marshal(struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue
	}{signedOID, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: sd}})
	require.NoError(t, err)
	for name, raw := range map[string][]byte{"DER": concatenated, "PEM": pemBytes, "P7B": p7b} {
		t.Run(name, func(t *testing.T) {
			parsed, err := ParseCertificates(raw)
			require.NoError(t, err)
			require.Len(t, parsed, 2)
			require.Equal(t, a.Raw, parsed[0].Raw)
			require.Equal(t, b.Raw, parsed[1].Raw)
		})
	}
}
