package keystore

import (
	"encoding/asn1"
	"math/big"
	"math/bits"
	"slices"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

func TestIITSeparateAgreementKey(t *testing.T) {
	marshal := func(value any) []byte { data, err := asn1.Marshal(value); require.NoError(t, err); return data }
	primary, err := dstu4145.GenerateKey(dstu4145.ParamsByName("DSTU_PB_257").Curve)
	require.NoError(t, err)
	agreement, err := dstu4145.GenerateKey(dstu4145.ParamsByName("DSTU_PB_431").Curve)
	require.NoError(t, err)
	raw, err := MarshalRawKey(primary)
	require.NoError(t, err)
	var key privateKeyInfo
	_, err = asn1.Unmarshal(raw, &key)
	require.NoError(t, err)
	c := agreement.Curve
	powers := []int{}
	for _, power := range c.ModBits {
		if power != 0 && power != c.M {
			powers = append(powers, power)
		}
	}
	slices.Sort(powers)
	polynomial := marshal(powers)
	if len(powers) == 1 {
		polynomial = marshal(powers[0])
	}
	parameters := marshal(struct {
		Curve struct {
			Field struct {
				M          int
				Polynomial asn1.RawValue
			}
			A    int
			B    []byte
			N    *big.Int
			Base []byte
		}
		DKE, Metadata []byte
	}{struct {
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
	}{c.M, asn1.RawValue{FullBytes: polynomial}}, int(new(big.Int).SetBytes(c.A.Bytes()).Int64()), c.B.Bytes(), new(big.Int).SetBytes(c.N), c.BasePoint().Compress()}, make([]byte, 64), make([]byte, 64)})
	scalar := make([]byte, (c.M+7)/8)
	agreement.D.FillBytes(scalar)
	slices.Reverse(scalar)
	for i, b := range scalar {
		scalar[i] = bits.Reverse8(b)
	}
	attributes := []keyAttribute{
		{OID: oidIITKEPParameters, Values: []asn1.RawValue{{FullBytes: parameters}}},
		{OID: oidIITKEPKey, Values: []asn1.RawValue{{FullBytes: marshal(asn1.BitString{Bytes: scalar, BitLength: len(scalar) * 8})}}},
	}
	encode := func(attrs []keyAttribute) []byte {
		return marshal(struct {
			Version    int
			Algorithm  pkcs8AlgorithmIdentifier
			PrivateKey []byte
			Attributes []keyAttribute `asn1:"optional,tag:0"`
		}{key.Version, key.Algorithm, key.PrivateKey, attrs})
	}
	parsed, err := parseRawKeys(encode(attributes))
	require.NoError(t, err)
	require.Len(t, parsed, 2)
	require.Equal(t, primary.Public(), parsed[0].Public())
	require.Equal(t, agreement.Public(), parsed[1].Public())
	// PFX export preserves the original PKCS#8 agreement-key attributes, not
	// just the first scalar exposed by ParseRawKey.
	pfx, err := MarshalPKCS12([][]byte{encode(attributes)}, [][]byte{
		testiit.Certificate(t, agreement, false).Raw,
		testiit.Certificate(t, primary, false).Raw,
	}, "disposable-pfx")
	require.NoError(t, err)
	pairs, err := ParsePKCS12(pfx, "disposable-pfx")
	require.NoError(t, err)
	require.Len(t, pairs, 2)
	require.Equal(t, primary.Public(), pairs[0].PrivateKey.Public())
	require.Equal(t, agreement.Public(), pairs[1].PrivateKey.Public())
	for _, tc := range []struct {
		name       string
		attributes []keyAttribute
	}{
		{"missing parameters", attributes[1:]},
		{"missing scalar", attributes[:1]},
		{"duplicate scalar", append(slices.Clone(attributes), attributes[1])},
		{"multiple values", []keyAttribute{{OID: oidIITKEPParameters, Values: attributes[0].Values}, {OID: oidIITKEPKey, Values: append(slices.Clone(attributes[1].Values), attributes[1].Values[0])}}},
		{"invalid curve", []keyAttribute{{OID: oidIITKEPParameters, Values: []asn1.RawValue{{FullBytes: marshal(struct {
			Curve         int
			DKE, Metadata []byte
		}{1, nil, nil})}}}, attributes[1]}},
		{"zero scalar", []keyAttribute{attributes[0], {OID: oidIITKEPKey, Values: []asn1.RawValue{{FullBytes: marshal(asn1.BitString{Bytes: make([]byte, len(scalar)), BitLength: len(scalar) * 8})}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := parseRawKeys(encode(tc.attributes))
			require.Error(t, err)
			require.Nil(t, out)
		})
	}
}
