package ec

import (
	"math/big"
	"testing"

	"github.com/amaneshi/crypto-dstu/pkg/gf2m"
	"github.com/stretchr/testify/require"
)

func TestONBReferenceConversions(t *testing.T) {
	// Independent public values from Cryptonite utest_dstu4145.c.
	for _, tc := range []struct {
		curve              *Curve
		normal, polynomial string
	}{
		{DSTU_ONB_173(), "1053bc43edb5401d73e045d608f6cd71a", "1cd30e064b7d1f84f2654dafefb6341a69ed2de6f7be"},
		{DSTU_ONB_173(), "043D7E139319F43BA00944915740E1E6651B06E278C7", "01eec7c8f700a6aedbd1461bfd4e13f7a34be03124b2"},
		{DSTU_ONB_179(), "19C9EBC4FD8308193D3A61762C547C82F2E6B2182CBCB", "4c8a1d80932e32d11d5cc8c5c61d708d9c7ec4072c6e0"},
		{DSTU_ONB_431(), "53FB7AF7B4407000A6F226AD6BAD28378646BD83F1F940810A4C19536EE65E53F40F973F2F06C5E80EFE3B43651BD5FF8B06BA5F9299", "513dc8305b5444dca36bf9c383216d191f9457d222eb612dea8cc5a073e37e17ed41b01d8152af26d45d676c728f814ba7f6014e4d55"},
	} {
		normal := mustFromHex(tc.normal, tc.curve.Words)
		polynomial := mustFromHex(tc.polynomial, tc.curve.Words)
		decoded, err := tc.curve.DecodeField(normal)
		require.NoError(t, err)
		require.True(t, polynomial.Equal(decoded))
		encoded, err := tc.curve.EncodeField(polynomial)
		require.NoError(t, err)
		require.True(t, normal.Equal(encoded))
	}
}

func TestONBDomainIdentity(t *testing.T) {
	pb, onb := DSTU_PB_173(), DSTU_ONB_173()
	require.Equal(t, pb.M, onb.M)
	require.Equal(t, pb.N, onb.N)
	require.False(t, pb.EqualDomain(onb))
	require.True(t, onb.EqualDomain(DSTU_ONB_173()))
}

func TestONBDomains(t *testing.T) {
	for _, curve := range []*Curve{DSTU_ONB_173(), DSTU_ONB_179(), DSTU_ONB_191(), DSTU_ONB_233(), DSTU_ONB_431()} {
		t.Run(curve.String(), func(t *testing.T) {
			require.True(t, curve.Contains(curve.BasePoint()))
			zeroPoint, err := curve.Expand(make([]byte, (curve.M+7)/8))
			require.NoError(t, err)
			require.True(t, curve.Contains(zeroPoint))
			require.False(t, zeroPoint.Inf)
			require.True(t, curve.ScalarBaseMul(new(big.Int).SetBytes(curve.N)).Inf)
			for i := range curve.M {
				e := curve.NewElement()
				e.SetBit(i)
				pb, err := curve.DecodeField(e)
				require.NoError(t, err)
				back, err := curve.EncodeField(pb)
				require.NoError(t, err)
				require.True(t, e.Equal(back), "basis column %d", i)
				// Squaring rotates normal-basis coefficients right by one.
				squared, err := curve.EncodeField(gf2m.ModSqr(pb, curve.ModBits))
				require.NoError(t, err)
				want := curve.NewElement()
				want.SetBit((i + curve.M - 1) % curve.M)
				require.True(t, squared.Equal(want))
			}
			for _, d := range []int64{1, 2, 3, 19} {
				point := curve.ScalarBaseMul(big.NewInt(d))
				expanded, err := curve.Expand(point.Compress())
				require.NoError(t, err)
				require.True(t, point.X.Equal(expanded.X))
				require.True(t, point.Y.Equal(expanded.Y))
			}
			tooLarge := curve.NewElement()
			tooLarge.SetBit(curve.M)
			_, err = curve.DecodeField(tooLarge)
			require.Error(t, err)
			_, err = curve.EncodeField(tooLarge)
			require.Error(t, err)
		})
	}
}
