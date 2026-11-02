package dstu15946

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

func TestPB173CryptoniteSharedSecret(t *testing.T) {
	data, err := os.ReadFile("testdata/pb173-cryptonite.json")
	require.NoError(t, err)
	var fixture struct {
		Producer, SourceCommit string
		Vectors                []struct {
			Degree                  int
			PeerCompressed, SharedX string
		}
	}
	require.NoError(t, json.Unmarshal(data, &fixture))
	require.Equal(t, "3618d340d22e27a6becf97d89c453f8e64068a39", fixture.SourceCommit)
	require.NotEmpty(t, fixture.Producer)
	require.Len(t, fixture.Vectors, 1)
	vector := fixture.Vectors[0]
	require.Equal(t, 173, vector.Degree)
	curve := dstu4145.ParamsByName("DSTU_PB_173").Curve
	require.Equal(t, 4, curve.Cofactor)
	compressed, err := hex.DecodeString(vector.PeerCompressed)
	require.NoError(t, err)
	peer, err := curve.Expand(compressed)
	require.NoError(t, err)
	secret, err := SharedSecret(&dstu4145.PrivateKey{Curve: curve, D: big.NewInt(2)}, &dstu4145.PublicKey{Curve: curve, Q: peer})
	require.NoError(t, err)
	expected, err := hex.DecodeString(vector.SharedX)
	require.NoError(t, err)
	require.Equal(t, expected, secret)
}
