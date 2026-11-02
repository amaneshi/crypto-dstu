package csr

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"slices"

	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/amaneshi/crypto-dstu/pkg/ec"
	"github.com/amaneshi/crypto-dstu/pkg/gf2m"
	"github.com/amaneshi/crypto-dstu/pkg/gost28147"
)

func validateRequestInfo(info certificationRequestInfo) error {
	var name pkix.RDNSequence
	if rest, err := asn1.Unmarshal(info.Subject.FullBytes, &name); err != nil || len(rest) != 0 {
		return errors.New("csr: invalid subject name")
	}
	if len(info.Attributes.FullBytes) == 0 {
		return nil
	} // old library writer
	if info.Attributes.Class != 2 || info.Attributes.Tag != 0 || !info.Attributes.IsCompound {
		return errors.New("csr: invalid attributes")
	}
	remaining := info.Attributes.Bytes
	var previous []byte
	for count := 0; len(remaining) > 0; count++ {
		if count >= 256 {
			return errors.New("csr: too many attributes")
		}
		var raw asn1.RawValue
		next, err := asn1.Unmarshal(remaining, &raw)
		if err != nil || raw.Class != 0 || raw.Tag != asn1.TagSequence || !raw.IsCompound {
			return errors.New("csr: malformed attribute")
		}
		var attribute struct {
			ID     asn1.ObjectIdentifier
			Values []asn1.RawValue `asn1:"set"`
		}
		if rest, err := asn1.Unmarshal(raw.FullBytes, &attribute); err != nil || len(rest) != 0 || len(attribute.Values) == 0 {
			return errors.New("csr: malformed attribute values")
		}
		canonical, err := asn1.Marshal(attribute)
		if err != nil || !bytes.Equal(canonical, raw.FullBytes) || previous != nil && bytes.Compare(previous, raw.FullBytes) > 0 {
			return errors.New("csr: noncanonical attributes")
		}
		previous = raw.FullBytes
		remaining = next
	}
	return nil
}

func checkSignatureProfile(algorithm asn1.ObjectIdentifier, curve *ec.Curve) error {
	if curve.IsONB() {
		if algorithm.Equal(oid.DSTU4145ONBWithGOST34311) {
			return nil
		}
	} else if algorithm.Equal(oid.DSTU4145WithGOST34311) || algorithm.Equal(oid.DSTU4145WithKupyna256) || algorithm.Equal(oid.DSTU4145WithKupyna512) {
		return nil
	}
	return errors.New("csr: unsupported signature algorithm or curve basis")
}

func hashNational(data []byte, algorithm asn1.ObjectIdentifier) ([]byte, error) {
	digest, err := hashData(data, algorithm)
	if err != nil {
		return nil, err
	}
	slices.Reverse(digest)
	return digest, nil
}

func buildNationalSPKI(key *dstu4145.PrivateKey, algorithm asn1.ObjectIdentifier) (subjectPublicKeyInfo, error) {
	curveOID := curveOIDForKey(key)
	if curveOID == nil {
		return subjectPublicKeyInfo{}, errors.New("csr: unknown curve")
	}
	var dke []byte
	if algorithm.Equal(oid.DSTU4145WithGOST34311) || algorithm.Equal(oid.DSTU4145ONBWithGOST34311) {
		dke = gost28147.SboxDSTU.Packed()
	}
	parameters, err := asn1.Marshal(struct {
		Curve asn1.ObjectIdentifier
		DKE   []byte `asn1:"optional"`
	}{curveOID, dke})
	if err != nil {
		return subjectPublicKeyInfo{}, err
	}
	compressed := key.Public().Q.Compress()
	slices.Reverse(compressed)
	encoded, err := asn1.Marshal(compressed)
	if err != nil {
		return subjectPublicKeyInfo{}, err
	}
	return subjectPublicKeyInfo{Algorithm: algorithmIdentifier{Algorithm: algorithm, Parameters: asn1.RawValue{FullBytes: parameters}}, PublicKey: asn1.BitString{Bytes: encoded, BitLength: len(encoded) * 8}}, nil
}

func parseNationalOrLegacySPKI(spki subjectPublicKeyInfo) (*dstu4145.PublicKey, bool, error) {
	if spki.PublicKey.BitLength != len(spki.PublicKey.Bytes)*8 {
		return nil, false, errors.New("csr: public key is not byte aligned")
	}
	params := dstu4145.ParamsByOID(spki.Algorithm.Algorithm)
	legacyParameters := params != nil
	if params == nil {
		var curveOID asn1.ObjectIdentifier
		if rest, err := asn1.Unmarshal(spki.Algorithm.Parameters.FullBytes, &curveOID); err == nil && len(rest) == 0 {
			params = dstu4145.ParamsByOID(curveOID)
			legacyParameters = params != nil
		}
	}
	if params == nil {
		params = dstu4145.ParamsFromDER(spki.Algorithm.Parameters.FullBytes)
	}
	if params == nil {
		return nil, false, errors.New("csr: unknown curve")
	}
	curve := params.Curve
	if err := checkSignatureProfile(spki.Algorithm.Algorithm, curve); err != nil && !spki.Algorithm.Algorithm.Equal(params.OID) {
		return nil, false, err
	}
	keyBytes, size := spki.PublicKey.Bytes, (curve.M+7)/8
	var compressed []byte
	if rest, err := asn1.Unmarshal(keyBytes, &compressed); !legacyParameters && err == nil && len(rest) == 0 {
		var parameters struct {
			Curve asn1.RawValue
			DKE   []byte `asn1:"optional"`
		}
		if rest, err := asn1.Unmarshal(spki.Algorithm.Parameters.FullBytes, &parameters); err == nil && len(rest) == 0 {
			gost := spki.Algorithm.Algorithm.Equal(oid.DSTU4145WithGOST34311) || spki.Algorithm.Algorithm.Equal(oid.DSTU4145ONBWithGOST34311)
			if len(parameters.DKE) != 0 && (!gost || !bytes.Equal(parameters.DKE, gost28147.SboxDSTU.Packed())) {
				return nil, false, errors.New("csr: unsupported DKE")
			}
		}
		if len(compressed) != size {
			return nil, false, errors.New("csr: invalid national public key length")
		}
		slices.Reverse(compressed)
		point, err := curve.Expand(compressed)
		if err != nil {
			return nil, false, err
		}
		if point.IsInfinity() || !point.ScalarMul(new(big.Int).SetBytes(curve.N)).IsInfinity() {
			return nil, false, errors.New("csr: public key outside signing subgroup")
		}
		return &dstu4145.PublicKey{Curve: curve, Q: point}, true, nil
	}
	// Read the old library encoding only when the key explicitly has its old
	// shape. Never retry a failed national signature using legacy digest rules.
	if !legacyParameters {
		return nil, false, errors.New("csr: invalid national public key encoding")
	}
	if curve.IsONB() {
		return nil, false, errors.New("csr: ONB requires national public key encoding")
	}
	var point *ec.Point
	if len(keyBytes) == 2*size {
		x := gf2m.FromBytes(keyBytes[:size], curve.Words)
		y := gf2m.FromBytes(keyBytes[size:], curve.Words)
		if x.BitLen() > curve.M || y.BitLen() > curve.M {
			return nil, false, errors.New("csr: public key outside field")
		}
		point = ec.NewPoint(curve, x, y)
	} else if len(keyBytes) == size {
		var err error
		point, err = curve.Expand(keyBytes)
		if err != nil {
			return nil, false, err
		}
	} else {
		return nil, false, errors.New("csr: invalid legacy public key length")
	}
	if !curve.Contains(point) || point.IsInfinity() || !point.ScalarMul(new(big.Int).SetBytes(curve.N)).IsInfinity() {
		return nil, false, errors.New("csr: invalid signing public key")
	}
	return &dstu4145.PublicKey{Curve: curve, Q: point}, false, nil
}
