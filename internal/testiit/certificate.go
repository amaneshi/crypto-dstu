// Package testiit supplies disposable fixtures for optional native IIT tests.
package testiit

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"hash"
	"math/big"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/amaneshi/crypto-dstu/pkg/gost28147"
	"github.com/amaneshi/crypto-dstu/pkg/gost34311"
	"github.com/amaneshi/crypto-dstu/pkg/kupyna"
	czo "github.com/amaneshi/crypto-dstu/testdata/czo"
	"github.com/stretchr/testify/require"
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

func reversed(input []byte) []byte {
	output := slices.Clone(input)
	slices.Reverse(output)
	return output
}

// Certificate uses standard explicit domain/DKE parameters with a new
// disposable identity and key. timestamping adds the exclusive critical TSA EKU.
func Certificate(t testing.TB, key *dstu4145.PrivateKey, timestamping bool) *cert.Certificate {
	return CertificateForDigest(t, key, timestamping, oid.GOST34311)
}

// CertificateForDigest builds an isolated certificate with explicit standard
// domain parameters and the chosen national certificate signature profile.
func CertificateForDigest(t testing.TB, key *dstu4145.PrivateKey, timestamping bool, digest asn1.ObjectIdentifier) *cert.Certificate {
	return certificateForDigest(t, key, timestamping, digest, 0xc8)
}

// AgreementCertificateForDigest creates a key-agreement-only identity.
func AgreementCertificateForDigest(t testing.TB, key *dstu4145.PrivateKey, digest asn1.ObjectIdentifier) *cert.Certificate {
	return certificateForDigest(t, key, false, digest, 0x08)
}

func certificateForDigest(t testing.TB, key *dstu4145.PrivateKey, timestamping bool, digest asn1.ObjectIdentifier, usage byte) *cert.Certificate {
	t.Helper()
	type extension struct {
		ID       asn1.ObjectIdentifier
		Critical bool `asn1:"optional"`
		Value    []byte
	}
	type publicKeyInfo struct {
		Algorithm algorithmIdentifier
		Key       asn1.BitString
	}
	type tbsCert struct {
		Version    int `asn1:"optional,explicit,tag:0,default:0"`
		Serial     *big.Int
		Signature  algorithmIdentifier
		Issuer     asn1.RawValue
		Validity   struct{ From, To time.Time }
		Subject    asn1.RawValue
		PublicKey  publicKeyInfo
		Extensions []extension `asn1:"optional,explicit,tag:3"`
	}
	var outer struct {
		TBS       asn1.RawValue
		Algorithm algorithmIdentifier
		Signature asn1.BitString
	}
	// Reuse the CZO ASN.1 envelope, then replace the explicit domain parameters.
	// Identity, key, extensions, validity and certificate signature are replaced.
	template, err := os.ReadFile(czo.Path("certs/DSTU/DSTU_sign.cer"))
	require.NoError(t, err)
	_, err = asn1.Unmarshal(template, &outer)
	require.NoError(t, err)
	var tbs tbsCert
	_, err = asn1.Unmarshal(outer.TBS.FullBytes, &tbs)
	require.NoError(t, err)
	parameters := explicitParameters(t, key, digest.Equal(oid.GOST34311))
	tbs.PublicKey.Algorithm.Parameters = asn1.RawValue{FullBytes: parameters}
	var signatureOID asn1.ObjectIdentifier
	var h hash.Hash
	switch {
	case digest.Equal(oid.GOST34311):
		signatureOID = oid.DSTU4145WithGOST34311
		h = gost34311.New()
	case digest.Equal(oid.Kupyna256):
		signatureOID = oid.DSTU4145WithKupyna256
		h = kupyna.New256()
	case digest.Equal(oid.Kupyna512):
		signatureOID = oid.DSTU4145WithKupyna512
		h = kupyna.New512()
	default:
		t.Fatal("unsupported fixture digest")
	}
	outer.Algorithm.Algorithm = signatureOID
	tbs.Signature.Algorithm = signatureOID
	name, err := asn1.Marshal(pkix.Name{CommonName: "crypto-dstu local interoperability test"}.ToRDNSequence())
	require.NoError(t, err)
	tbs.Serial, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	require.NoError(t, err)
	tbs.Serial.Add(tbs.Serial, big.NewInt(1))
	tbs.Issuer = asn1.RawValue{FullBytes: name}
	tbs.Subject = tbs.Issuer
	tbs.Validity.From = time.Now().UTC().Add(-24 * time.Hour)
	tbs.Validity.To = time.Now().UTC().Add(24 * time.Hour)
	compressed := reversed(key.Public().Q.Compress())
	keyOctet, err := asn1.Marshal(compressed)
	require.NoError(t, err)
	tbs.PublicKey.Key = asn1.BitString{Bytes: keyOctet, BitLength: len(keyOctet) * 8}
	keyIDProfile := digest
	if digest.Equal(oid.Kupyna512) {
		keyIDProfile = oid.Kupyna256
	}
	keyHash := profileHash(keyIDProfile)
	keyHash.Write(keyOctet)
	id := keyHash.Sum(nil)
	ski, err := asn1.Marshal(id)
	require.NoError(t, err)
	aki, err := asn1.Marshal(struct {
		ID []byte `asn1:"tag:0"`
	}{id})
	require.NoError(t, err)
	bc, err := asn1.Marshal(struct {
		CA bool `asn1:"optional"`
	}{false})
	require.NoError(t, err)
	ku, err := asn1.Marshal(asn1.BitString{Bytes: []byte{usage}, BitLength: 5})
	require.NoError(t, err)
	tbs.Extensions = []extension{{oid.OIDExtSubjectKeyID, false, ski}, {oid.OIDExtAuthorityKeyID, false, aki}, {oid.OIDExtBasicConstraints, true, bc}, {oid.OIDExtKeyUsage, true, ku}}
	if timestamping {
		eku, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
		require.NoError(t, err)
		tbs.Extensions = append(tbs.Extensions, extension{asn1.ObjectIdentifier{2, 5, 29, 37}, true, eku})
	}
	raw, err := asn1.Marshal(tbs)
	require.NoError(t, err)
	h.Write(raw)
	sig, err := dstu4145.Sign(rand.Reader, key, reversed(h.Sum(nil)))
	require.NoError(t, err)
	sigBytes, err := dstu4145.MarshalSignatureRaw(sig, key.Curve)
	require.NoError(t, err)
	wrapped, err := asn1.Marshal(sigBytes)
	require.NoError(t, err)
	outer.TBS = asn1.RawValue{FullBytes: raw}
	outer.Signature = asn1.BitString{Bytes: wrapped, BitLength: len(wrapped) * 8}
	der, err := asn1.Marshal(outer)
	require.NoError(t, err)
	c, err := cert.ParseCertificate(der)
	require.NoError(t, err)
	require.NoError(t, cert.VerifyCertPKMatch(c, key))
	require.NoError(t, cert.VerifyCert(c, c))
	return c
}

func explicitParameters(t testing.TB, key *dstu4145.PrivateKey, includeDKE bool) []byte {
	t.Helper()
	c := key.Curve
	var powers []int
	for _, power := range c.ModBits {
		if power != 0 && power != c.M {
			powers = append(powers, power)
		}
	}
	slices.Sort(powers)
	var polynomial []byte
	var err error
	if len(powers) == 1 {
		polynomial, err = asn1.Marshal(powers[0])
	} else {
		polynomial, err = asn1.Marshal(powers)
	}
	require.NoError(t, err)
	b := new(big.Int).SetBytes(c.B.Bytes()).FillBytes(make([]byte, (c.M+7)/8))
	explicit := struct {
		Field struct {
			M          int
			Polynomial asn1.RawValue
		}
		A    int
		B    []byte
		N    *big.Int
		Base []byte
	}{struct {
		M          int
		Polynomial asn1.RawValue
	}{c.M, asn1.RawValue{FullBytes: polynomial}}, int(new(big.Int).SetBytes(c.A.Bytes()).Int64()), reversed(b), new(big.Int).SetBytes(c.N), reversed(c.BasePoint().Compress())}
	encoded, err := asn1.Marshal(explicit)
	require.NoError(t, err)
	var dke []byte
	if includeDKE {
		dke = gost28147.SboxDSTU.Packed()
	}
	parameters, err := asn1.Marshal(struct {
		Curve asn1.RawValue
		DKE   []byte `asn1:"optional"`
	}{asn1.RawValue{FullBytes: encoded}, dke})
	require.NoError(t, err)
	require.NotNil(t, dstu4145.ParamsFromDER(parameters), "fixture parameters must match a built-in curve")
	return parameters
}

func profileHash(digest asn1.ObjectIdentifier) hash.Hash {
	switch {
	case digest.Equal(oid.GOST34311):
		return gost34311.New()
	case digest.Equal(oid.Kupyna256):
		return kupyna.New256()
	case digest.Equal(oid.Kupyna512):
		return kupyna.New512()
	}
	panic("unsupported test profile")
}
