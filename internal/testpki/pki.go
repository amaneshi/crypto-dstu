// Package testpki generates disposable DSTU certificates and signed OCSP fixtures
// for tests. It is not imported by the library's runtime packages.
package testpki

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/amaneshi/crypto-dstu/pkg/gost34311"
)

type algorithm struct {
	OID        asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

func mustDER(t testing.TB, value any) []byte {
	t.Helper()
	der, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
func sign(t testing.TB, data []byte, key *dstu4145.PrivateKey) asn1.BitString {
	t.Helper()
	h := gost34311.New()
	h.Write(data)
	digest := h.Sum(nil)
	slices.Reverse(digest)
	sig, err := dstu4145.Sign(rand.Reader, key, digest)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dstu4145.MarshalSignatureRaw(sig, key.Curve)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := mustDER(t, raw)
	return asn1.BitString{Bytes: wrapped, BitLength: len(wrapped) * 8}
}

func CAExtensions(t testing.TB) []pkix.Extension {
	t.Helper()
	return []pkix.Extension{
		{Id: oid.OIDExtBasicConstraints, Critical: true, Value: mustDER(t, struct{ CA bool }{true})},
		{Id: oid.OIDExtKeyUsage, Critical: true, Value: mustDER(t, asn1.BitString{Bytes: []byte{0x86}, BitLength: 7})},
	}
}

// Issue creates a real DER certificate using a named PB257 curve. Nil issuer
// creates a self-signed certificate; otherwise issuerKey signs the new key.
func Issue(t testing.TB, name string, issuer *cert.Certificate, issuerKey *dstu4145.PrivateKey, extensions []pkix.Extension) (*cert.Certificate, *dstu4145.PrivateKey) {
	t.Helper()
	return IssueWithOptions(
		t, name, issuer, issuerKey, CertificateOptions{Extensions: extensions},
	)
}

// CertificateOptions permits fixed public test keys/identities across fuzz workers.
type CertificateOptions struct {
	Key                 *dstu4145.PrivateKey
	Serial              *big.Int
	NotBefore, NotAfter time.Time
	Extensions          []pkix.Extension
}

// IssueWithOptions issues a test certificate; zero options retain Issue defaults.
func IssueWithOptions(
	t testing.TB,
	name string,
	issuer *cert.Certificate,
	issuerKey *dstu4145.PrivateKey,
	options CertificateOptions,
) (*cert.Certificate, *dstu4145.PrivateKey) {
	t.Helper()
	key := options.Key
	if key == nil {
		var err error
		key, err = dstu4145.GenerateKey(dstu4145.ParamsByName("DSTU_PB_257").Curve)
		if err != nil {
			t.Fatal(err)
		}
	}
	subject := mustDER(t, pkix.Name{CommonName: name}.ToRDNSequence())
	issuerName := subject
	if issuer == nil {
		issuerKey = key
	} else {
		issuerName = issuer.Subject.FullBytes
	}
	serial := options.Serial
	if serial == nil {
		var err error
		serial, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
		if err != nil {
			t.Fatal(err)
		}
		serial.Add(serial, big.NewInt(1))
	}
	if options.NotBefore.IsZero() {
		options.NotBefore = time.Now().Add(-time.Hour)
	}
	if options.NotAfter.IsZero() {
		options.NotAfter = time.Now().Add(24 * time.Hour)
	}
	compressed := key.Public().Q.Compress()
	slices.Reverse(compressed)
	pub := mustDER(t, compressed)
	params := mustDER(t, struct{ Curve asn1.ObjectIdentifier }{oid.CurvePB257})
	alg := algorithm{OID: oid.DSTU4145WithGOST34311}
	tbs := mustDER(t, struct {
		Version   int `asn1:"explicit,tag:0"`
		Serial    *big.Int
		Signature algorithm
		Issuer    asn1.RawValue
		Validity  struct{ From, To time.Time }
		Subject   asn1.RawValue
		SPKI      struct {
			Algorithm algorithm
			Key       asn1.BitString
		}
		Extensions []pkix.Extension `asn1:"optional,explicit,tag:3"`
	}{2, serial, alg, asn1.RawValue{FullBytes: issuerName}, struct{ From, To time.Time }{options.NotBefore, options.NotAfter}, asn1.RawValue{FullBytes: subject}, struct {
		Algorithm algorithm
		Key       asn1.BitString
	}{algorithm{OID: oid.DSTU4145WithGOST34311, Parameters: asn1.RawValue{FullBytes: params}}, asn1.BitString{Bytes: pub, BitLength: len(pub) * 8}}, options.Extensions})
	der := mustDER(t, struct {
		TBS       asn1.RawValue
		Algorithm algorithm
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, alg, sign(t, tbs, issuerKey)})
	c, err := cert.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

type OCSPOptions struct {
	Status                             int
	ThisUpdate, NextUpdate, ProducedAt time.Time
	OmitNextUpdate                     bool
	ByKey                              bool
	Serial                             *big.Int
	NameHash, KeyHash                  []byte
	StatusValue                        *asn1.RawValue
	Duplicate                          bool
	Extensions                         []pkix.Extension
}

// OCSP independently encodes RFC 6960 ASN.1 with SHA-1 CertID and a national
// GOST/DSTU signature. A delegated signer's certificate is included automatically.
func OCSP(t testing.TB, subject, issuer, responder *cert.Certificate, key *dstu4145.PrivateKey, options OCSPOptions) []byte {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	if options.ThisUpdate.IsZero() {
		options.ThisUpdate = now.Add(-time.Minute)
	}
	if options.ProducedAt.IsZero() {
		options.ProducedAt = now.Add(-30 * time.Second)
	}
	if options.NextUpdate.IsZero() && !options.OmitNextUpdate {
		options.NextUpdate = now.Add(time.Hour)
	}
	nameHash, keyHash := sha1.Sum(issuer.Subject.FullBytes), sha1.Sum(issuer.SubjectPublicKeyBytes)
	if options.NameHash == nil {
		options.NameHash = nameHash[:]
	}
	if options.KeyHash == nil {
		options.KeyHash = keyHash[:]
	}
	if options.Serial == nil {
		options.Serial = subject.SerialNumber
	}
	status := asn1.RawValue{Class: 2, Tag: options.Status}
	if options.Status == 1 {
		var revoked asn1.RawValue
		asn1.Unmarshal(mustDER(t, struct {
			Time time.Time `asn1:"generalized"`
		}{now.Add(-time.Hour)}), &revoked)
		status.IsCompound = true
		status.Bytes = revoked.Bytes
	}
	if options.StatusValue != nil {
		status = *options.StatusValue
	}
	type id struct {
		Algorithm         algorithm
		NameHash, KeyHash []byte
		Serial            *big.Int
	}
	type single struct {
		ID         id
		Status     asn1.RawValue
		ThisUpdate time.Time `asn1:"generalized"`
		NextUpdate time.Time `asn1:"optional,explicit,tag:0,generalized"`
	}
	responses := []single{{id{algorithm{OID: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}}, options.NameHash, options.KeyHash, options.Serial}, status, options.ThisUpdate, options.NextUpdate}}
	if options.Duplicate {
		responses = append(responses, responses[0])
	}
	responderID := asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: responder.Subject.FullBytes}
	if options.ByKey {
		hash := sha1.Sum(responder.SubjectPublicKeyBytes)
		responderID = asn1.RawValue{Class: 2, Tag: 2, IsCompound: true, Bytes: mustDER(t, hash[:])}
	}
	tbs := mustDER(t, struct {
		Responder  asn1.RawValue
		ProducedAt time.Time `asn1:"generalized"`
		Responses  []single
		Extensions []pkix.Extension `asn1:"optional,explicit,tag:1"`
	}{responderID, options.ProducedAt, responses, options.Extensions})
	certificates := asn1.RawValue{}
	if responder != issuer {
		certificates = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: mustDER(t, []asn1.RawValue{{FullBytes: responder.Raw}})}
	}
	basic := mustDER(t, struct {
		TBS          asn1.RawValue
		Algorithm    algorithm
		Signature    asn1.BitString
		Certificates asn1.RawValue `asn1:"optional,explicit,tag:0"`
	}{asn1.RawValue{FullBytes: tbs}, algorithm{OID: oid.DSTU4145WithGOST34311}, sign(t, tbs, key), certificates})
	return mustDER(t, struct {
		Status asn1.Enumerated
		Bytes  struct {
			OID      asn1.ObjectIdentifier
			Response []byte
		} `asn1:"explicit,tag:0"`
	}{0, struct {
		OID      asn1.ObjectIdentifier
		Response []byte
	}{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}, basic}})
}

// CRLOptions controls independently encoded full CRL fixtures.
type CRLOptions struct {
	ThisUpdate, NextUpdate time.Time
	Revoked                []pkix.RevokedCertificate
	Extensions             []pkix.Extension
}

func CRL(t testing.TB, issuer *cert.Certificate, key *dstu4145.PrivateKey, options CRLOptions) []byte {
	t.Helper()
	if options.ThisUpdate.IsZero() {
		options.ThisUpdate = time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	}
	if options.NextUpdate.IsZero() {
		options.NextUpdate = time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	}
	alg := algorithm{OID: oid.DSTU4145WithGOST34311}
	tbs := mustDER(t, struct {
		Version                int
		Algorithm              algorithm
		Issuer                 asn1.RawValue
		ThisUpdate, NextUpdate time.Time
		Revoked                []pkix.RevokedCertificate `asn1:"optional"`
		Extensions             []pkix.Extension          `asn1:"optional,explicit,tag:0"`
	}{1, alg, asn1.RawValue{FullBytes: issuer.Subject.FullBytes}, options.ThisUpdate, options.NextUpdate, options.Revoked, options.Extensions})
	return mustDER(t, struct {
		TBS       asn1.RawValue
		Algorithm algorithm
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, alg, sign(t, tbs, key)})
}
