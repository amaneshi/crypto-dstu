// Package testtimestamp builds disposable timestamp fixtures for tests only.
package testtimestamp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"crypto-dstu/internal/cert"
	"crypto-dstu/internal/cms"
	"crypto-dstu/internal/oid"
	"crypto-dstu/internal/tsp"
	"crypto-dstu/pkg/dstu4145"
)

func der(t testing.TB, value any) []byte {
	t.Helper()
	b, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func Extensions(t testing.TB) []pkix.Extension {
	return []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: der(t, []asn1.ObjectIdentifier{tsp.OIDTimeStamping})}}
}
func Token(t testing.TB, signature []byte, tsa *cert.Certificate, key *dstu4145.PrivateKey, change func(*tsp.TSTInfo)) []byte {
	t.Helper()
	imprint, err := tsp.HashData(signature, oid.GOST34311)
	if err != nil {
		t.Fatal(err)
	}
	info := tsp.TSTInfo{Version: 1, Policy: asn1.ObjectIdentifier{1, 2, 3, 4}, MessageImprint: tsp.MessageImprint{HashAlgorithm: tsp.AlgorithmIdentifier{Algorithm: oid.GOST34311}, HashedMessage: imprint}, SerialNumber: big.NewInt(1), GenTime: time.Now().UTC().Truncate(time.Second)}
	if change != nil {
		change(&info)
	}
	token, err := cms.Sign(der(t, info), key, tsa, cms.SignOptions{ContentType: tsp.OIDTSTInfo})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// Attach encodes the unsigned signature timestamp using independent ASN.1
// assembly, preserving the original signature bytes and every signed attribute.
func Attach(t testing.TB, document, token []byte) []byte {
	t.Helper()
	children := func(der []byte) []asn1.RawValue {
		var outer asn1.RawValue
		if rest, err := asn1.Unmarshal(der, &outer); err != nil || len(rest) != 0 {
			t.Fatal("bad fixture DER")
		}
		var values []asn1.RawValue
		rest := outer.Bytes
		for len(rest) > 0 {
			var v asn1.RawValue
			var err error
			rest, err = asn1.Unmarshal(rest, &v)
			if err != nil {
				t.Fatal(err)
			}
			values = append(values, v)
		}
		return values
	}
	wrap := func(tag, class int, values []asn1.RawValue) asn1.RawValue {
		var b []byte
		for _, v := range values {
			b = append(b, v.FullBytes...)
		}
		return asn1.RawValue{FullBytes: der(t, asn1.RawValue{Class: class, Tag: tag, IsCompound: true, Bytes: b})}
	}
	ci := children(document)
	sd := children(ci[1].Bytes)
	signers := children(sd[len(sd)-1].FullBytes)
	signer := children(signers[0].FullBytes)
	attr := der(t, struct {
		OID    asn1.ObjectIdentifier
		Values asn1.RawValue
	}{tsp.OIDSignatureTimeStamp, wrap(17, 0, []asn1.RawValue{{FullBytes: token}})})
	signer = append(signer, wrap(1, 2, []asn1.RawValue{{FullBytes: attr}}))
	signers[0] = wrap(16, 0, signer)
	sd[len(sd)-1] = wrap(17, 0, signers)
	ci[1] = wrap(0, 2, []asn1.RawValue{wrap(16, 0, sd)})
	return wrap(16, 0, ci).FullBytes
}
