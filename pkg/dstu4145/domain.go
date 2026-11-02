package dstu4145

import (
	"bytes"
	"encoding/asn1"
	"math/big"
	"slices"
)

// ParamsFromDER resolves named or explicit little-endian DSTU domain parameters
// to one of the built-in curves. Explicit parameters must match the entire curve.
func ParamsFromDER(der []byte) *DomainParams {
	var parameters struct {
		Curve asn1.RawValue
		DKE   []byte `asn1:"optional"`
	}
	if rest, err := asn1.Unmarshal(der, &parameters); err != nil || len(rest) != 0 {
		return nil
	}
	var name asn1.ObjectIdentifier
	if rest, err := asn1.Unmarshal(parameters.Curve.FullBytes, &name); err == nil && len(rest) == 0 {
		return ParamsByOID(name)
	}
	var explicit struct {
		Field struct {
			M          int
			Polynomial asn1.RawValue
		}
		A    int
		B    []byte
		N    *big.Int
		Base []byte
	}
	if rest, err := asn1.Unmarshal(parameters.Curve.FullBytes, &explicit); err != nil || len(rest) != 0 || explicit.N == nil {
		return nil
	}
	var powers []int
	var power int
	if rest, err := asn1.Unmarshal(explicit.Field.Polynomial.FullBytes, &power); err == nil && len(rest) == 0 {
		powers = []int{power}
	} else if rest, err := asn1.Unmarshal(explicit.Field.Polynomial.FullBytes, &powers); err != nil || len(rest) != 0 {
		return nil
	}
	powers = append(powers, explicit.Field.M, 0)
	slices.Sort(powers)
	for i := range allParams {
		p := &allParams[i]
		c := p.Curve
		mod := slices.Clone(c.ModBits)
		slices.Sort(mod)
		if c.M != explicit.Field.M || !slices.Equal(mod, powers) || new(big.Int).SetBytes(c.A.Bytes()).Cmp(big.NewInt(int64(explicit.A))) != 0 || new(big.Int).SetBytes(c.N).Cmp(explicit.N) != 0 {
			continue
		}
		b := bytes.Clone(explicit.B)
		base := bytes.Clone(explicit.Base)
		slices.Reverse(b)
		slices.Reverse(base)
		encodedB, err := c.EncodeField(c.B)
		if err != nil {
			continue
		}
		if new(big.Int).SetBytes(b).Cmp(new(big.Int).SetBytes(encodedB.Bytes())) == 0 && bytes.Equal(base, c.BasePoint().Compress()) {
			return p
		}
	}
	return nil
}
