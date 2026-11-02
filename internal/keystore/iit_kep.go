package keystore

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"math/big"
	"math/bits"
	"slices"

	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
)

var (
	oidIITKEPParameters = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 19398, 1, 1, 2, 2}
	oidIITKEPKey        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 19398, 1, 1, 2, 3}
)

type keyAttribute struct {
	OID    asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// parseRawKeys preserves the primary key and IIT's optional separate agreement
// key. IIT KEP attributes use big-endian curve coordinates and bit-reversed
// little-endian scalar bytes, unlike the outer signing-key encoding.
func parseRawKeys(data []byte) ([]*dstu4145.PrivateKey, error) {
	primary, err := ParseRawKey(data)
	if err != nil {
		return nil, err
	}
	var info struct {
		Version    int
		Algorithm  pkcs8AlgorithmIdentifier
		PrivateKey []byte
		Attributes []keyAttribute `asn1:"optional,tag:0"`
	}
	if rest, err := asn1.Unmarshal(data, &info); err != nil || len(rest) != 0 {
		return nil, errors.New("keystore: invalid PKCS8 attributes")
	}
	var parameters, key []byte
	for _, attribute := range info.Attributes {
		var target *[]byte
		switch {
		case attribute.OID.Equal(oidIITKEPParameters):
			target = &parameters
		case attribute.OID.Equal(oidIITKEPKey):
			target = &key
		default:
			continue
		}
		if *target != nil || len(attribute.Values) != 1 {
			return nil, errors.New("keystore: duplicate or ambiguous IIT KEP attribute")
		}
		*target = attribute.Values[0].FullBytes
	}
	if parameters == nil && key == nil {
		return []*dstu4145.PrivateKey{primary}, nil
	}
	if parameters == nil || key == nil {
		return nil, errors.New("keystore: incomplete IIT KEP attributes")
	}
	var p struct {
		Curve         asn1.RawValue
		DKE, Metadata []byte
	}
	if rest, err := asn1.Unmarshal(parameters, &p); err != nil || len(rest) != 0 {
		return nil, errors.New("keystore: invalid IIT KEP parameters")
	}
	canonical, err := asn1.Marshal(p)
	if err != nil || !bytes.Equal(canonical, parameters) {
		return nil, errors.New("keystore: noncanonical IIT KEP parameters")
	}
	var curve struct {
		Field struct {
			M          int
			Polynomial asn1.RawValue
		}
		A    int
		B    []byte
		N    *big.Int
		Base []byte
	}
	if rest, err := asn1.Unmarshal(p.Curve.FullBytes, &curve); err != nil || len(rest) != 0 {
		return nil, errors.New("keystore: invalid IIT KEP curve")
	}
	encodedCurve, err := asn1.Marshal(curve)
	if err != nil || !bytes.Equal(encodedCurve, p.Curve.FullBytes) {
		return nil, errors.New("keystore: noncanonical IIT KEP curve")
	}
	slices.Reverse(curve.B)
	slices.Reverse(curve.Base)
	curveDER, err := asn1.Marshal(curve)
	if err != nil {
		return nil, err
	}
	normalized, err := asn1.Marshal(struct{ Curve asn1.RawValue }{asn1.RawValue{FullBytes: curveDER}})
	if err != nil {
		return nil, err
	}
	domain := dstu4145.ParamsFromDER(normalized)
	if domain == nil {
		return nil, errors.New("keystore: unsupported IIT KEP curve")
	}
	var scalar asn1.BitString
	if rest, err := asn1.Unmarshal(key, &scalar); err != nil || len(rest) != 0 || scalar.BitLength != len(scalar.Bytes)*8 || len(scalar.Bytes) != (domain.Curve.M+7)/8 {
		return nil, errors.New("keystore: invalid IIT KEP scalar encoding")
	}
	decoded := bytes.Clone(scalar.Bytes)
	defer clear(decoded)
	for i, b := range decoded {
		decoded[i] = bits.Reverse8(b)
	}
	slices.Reverse(decoded)
	d := new(big.Int).SetBytes(decoded)
	if d.Sign() <= 0 || d.Cmp(new(big.Int).SetBytes(domain.Curve.N)) >= 0 {
		return nil, errors.New("keystore: IIT KEP scalar out of range")
	}
	return []*dstu4145.PrivateKey{primary, {D: d, Curve: domain.Curve}}, nil
}
