package dstu15946

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/amaneshi/crypto-dstu/pkg/ec"
	"github.com/amaneshi/crypto-dstu/pkg/gf2m"
	"github.com/stretchr/testify/require"
)

func TestStandardDHIndependentVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/standard-dh-cryptonite.json")
	require.NoError(t, err)
	var fixture struct {
		Producer, SourceCommit string
		Vectors                []struct{ Curve, PeerX, PeerY, SharedX string }
	}
	require.NoError(t, json.Unmarshal(data, &fixture))
	require.Equal(t, "3618d340d22e27a6becf97d89c453f8e64068a39", fixture.SourceCommit)
	require.Contains(t, fixture.Producer, "with_cofactor=false")
	require.Len(t, fixture.Vectors, 15)
	decode := func(s string) []byte { b, err := hex.DecodeString(s); require.NoError(t, err); return b }
	seen := make(map[string]bool)
	for _, v := range fixture.Vectors {
		require.False(t, seen[v.Curve])
		seen[v.Curve] = true
		t.Run(v.Curve, func(t *testing.T) {
			curve := dstu4145.ParamsByName(v.Curve).Curve
			x, err := curve.DecodeField(gf2m.FromBytes(decode(v.PeerX), curve.Words))
			require.NoError(t, err)
			y, err := curve.DecodeField(gf2m.FromBytes(decode(v.PeerY), curve.Words))
			require.NoError(t, err)
			peer := &dstu4145.PublicKey{Curve: curve, Q: ec.NewPoint(curve, x, y)}
			key := &dstu4145.PrivateKey{Curve: curve, D: big.NewInt(2)}
			secret, err := SharedSecretStandard(key, peer)
			require.NoError(t, err)
			require.Equal(t, decode(v.SharedX), secret)
			cofactor, err := SharedSecret(key, peer)
			require.NoError(t, err)
			require.NotEqual(t, cofactor, secret, "agreement schemes must remain distinct")
		})
	}
}

func TestStandardDHRejectsInconsistentDomains(t *testing.T) {
	pb, onb := dstu4145.ParamsByName("DSTU_PB_173").Curve, dstu4145.ParamsByName("DSTU_ONB_173").Curve
	key := &dstu4145.PrivateKey{Curve: onb, D: big.NewInt(2)}
	peer := (&dstu4145.PrivateKey{Curve: onb, D: big.NewInt(7)}).Public()
	for _, pointCurve := range []*ec.Curve{nil, pb} {
		point := *peer.Q
		point.Curve = pointCurve
		secret, err := SharedSecretStandard(key, &dstu4145.PublicKey{Curve: onb, Q: &point})
		require.Error(t, err)
		require.Nil(t, secret)
	}
	secret, err := SharedSecretStandard(key, (&dstu4145.PrivateKey{Curve: pb, D: big.NewInt(7)}).Public())
	require.Error(t, err)
	require.Nil(t, secret)
}

func TestStandardDHRejectsSmallAndMixedOrderPeers(t *testing.T) {
	for _, params := range dstu4145.AllParams() {
		t.Run(params.Name, func(t *testing.T) {
			curve := params.Curve
			key := &dstu4145.PrivateKey{Curve: curve, D: big.NewInt(2)}
			peer := (&dstu4145.PrivateKey{Curve: curve, D: big.NewInt(7)}).Public()
			orderTwo, err := curve.Expand([]byte{0})
			require.NoError(t, err)
			for _, point := range []*ec.Point{orderTwo, peer.Q.Add(orderTwo)} {
				require.True(t, curve.Contains(point))
				secret, err := SharedSecretStandard(key, &dstu4145.PublicKey{Curve: curve, Q: point})
				require.ErrorContains(t, err, "prime-order subgroup")
				require.Nil(t, secret)
			}
			secret, err := SharedSecretStandard(key, &dstu4145.PublicKey{Curve: curve, Q: ec.Infinity(curve)})
			require.Error(t, err)
			require.Nil(t, secret)
			outside := *peer.Q
			outside.X = peer.Q.X.Clone()
			outside.X.SetBit(curve.M)
			secret, err = SharedSecretStandard(key, &dstu4145.PublicKey{Curve: curve, Q: &outside})
			require.ErrorContains(t, err, "outside the field")
			require.Nil(t, secret)
			for _, d := range []*big.Int{big.NewInt(0), new(big.Int).SetBytes(curve.N)} {
				secret, err := SharedSecretStandard(&dstu4145.PrivateKey{Curve: curve, D: d}, peer)
				require.Error(t, err)
				require.Nil(t, secret)
			}
		})
	}
}
