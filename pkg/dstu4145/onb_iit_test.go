package dstu4145_test

import (
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"slices"
	"testing"

	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/amaneshi/crypto-dstu/pkg/gost34311"
	"github.com/stretchr/testify/require"
)

// Identifiers returned by EUGetKeyInfoBinary, IIT x86 1.3.1.224, DLL SHA256
// 475539dd6b01015e73cf3d143783c3f164c3f9db1e92e724c6f6493f086d9f4f.
// The input is a Key-6 containing a deliberately public full-width scalar;
// the native provider derives the public point independently. No Go-generated
// certificate or point is provided to this native operation. See docs/onb.md.
func TestIITONBPublicKeyIdentifiers(t *testing.T) {
	for _, tc := range []struct{ name, identifier string }{
		{"DSTU_ONB_173", "dc6c7716de982356bd6b24e24f32b45181ea9dacd1b66469d174db2629f0132f"},
		{"DSTU_ONB_179", "c1643ccf4adc3b6e41791c9f89719f4b5440d5397f3409499d0a141476af7a96"},
		{"DSTU_ONB_191", "1f2babf92d3d112fe3ce47e5a1f379d2ebc6f499ea25f6d8097d2c9d0eeaeb1a"},
		{"DSTU_ONB_233", "1677d757b38e6d6803d93b407f97d49820a45bfb0cc85a9bbb52ffb1038d6a5b"},
		{"DSTU_ONB_431", "cc44d68976f36dea933d74269e8a22e025cfd0ec215f91daea37e553d16487cc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			curve := dstu4145.ParamsByName(tc.name).Curve
			nBits := new(big.Int).SetBytes(curve.N).BitLen()
			d := new(big.Int).Lsh(big.NewInt(1), uint(nBits-2))
			d.Add(d, big.NewInt(0x12345))
			point := (&dstu4145.PrivateKey{Curve: curve, D: d}).Public().Q
			compressed := point.Compress()
			expanded, err := curve.Expand(compressed)
			require.NoError(t, err)
			require.True(t, point.X.Equal(expanded.X))
			require.True(t, point.Y.Equal(expanded.Y))
			changed := slices.Clone(compressed)
			changed[0] ^= byte(1 << uint((curve.M-1)%8))
			negative, err := curve.Expand(changed)
			require.NoError(t, err)
			require.True(t, point.Neg().Equal(negative), "selector must choose the other y coordinate")
			slices.Reverse(compressed)
			encoded, err := asn1.Marshal(compressed)
			require.NoError(t, err)
			h := gost34311.New()
			h.Write(encoded)
			require.Equal(t, tc.identifier, hex.EncodeToString(h.Sum(nil)))
		})
	}
}
