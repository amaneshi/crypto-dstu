package dstu4145_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/amaneshi/crypto-dstu/pkg/dstu15946"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/amaneshi/crypto-dstu/pkg/gf2m"
	"github.com/stretchr/testify/require"
)

func TestONBCryptoniteOperations(t *testing.T) {
	for _, name := range []string{"onb-operations-cryptonite.json", "onb-zero-digest-cryptonite.json"} {
		t.Run(name, func(t *testing.T) { checkONBCryptoniteOperations(t, "testdata/"+name) })
	}
}

func checkONBCryptoniteOperations(t *testing.T, path string) {
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var fixture struct {
		Producer, SourceCommit string
		Vectors                []struct {
			Degree                                                    int
			Digest, Qx, Qy, Compressed, PeerCompressed, SharedX, R, S string
		}
	}
	require.NoError(t, json.Unmarshal(data, &fixture))
	require.NotEmpty(t, fixture.Producer)
	require.Equal(t, "3618d340d22e27a6becf97d89c453f8e64068a39", fixture.SourceCommit)
	require.Len(t, fixture.Vectors, 5)
	decode := func(value string) []byte { b, err := hex.DecodeString(value); require.NoError(t, err); return b }
	for _, v := range fixture.Vectors {
		t.Run(fmt.Sprint(v.Degree), func(t *testing.T) {
			curve := dstu4145.ParamsByName(fmt.Sprintf("DSTU_ONB_%d", v.Degree)).Curve
			key := &dstu4145.PrivateKey{Curve: curve, D: big.NewInt(2)}
			pub := key.Public()
			x, err := curve.EncodeField(pub.Q.X)
			require.NoError(t, err)
			y, err := curve.EncodeField(pub.Q.Y)
			require.NoError(t, err)
			require.Equal(t, new(big.Int).SetBytes(decode(v.Qx)), new(big.Int).SetBytes(x.Bytes()))
			require.Equal(t, new(big.Int).SetBytes(decode(v.Qy)), new(big.Int).SetBytes(y.Bytes()))
			require.Equal(t, decode(v.Compressed), pub.Q.Compress())
			peer, err := curve.Expand(decode(v.PeerCompressed))
			require.NoError(t, err)
			secret, err := dstu15946.SharedSecret(key, &dstu4145.PublicKey{Curve: curve, Q: peer})
			require.NoError(t, err)
			require.Equal(t, decode(v.SharedX), secret)
			sig := &dstu4145.Signature{R: gf2m.FromBytes(decode(v.R), curve.Words), S: new(big.Int).SetBytes(decode(v.S))}
			digest := decode(v.Digest)
			require.True(t, dstu4145.Verify(pub, digest, sig), "independent Cryptonite signature")
			// With a deliberately public d, recover the known nonce and reproduce
			// the independent signature. This checks signing as well as verification.
			n := new(big.Int).SetBytes(curve.N)
			e := new(big.Int).Mul(key.D, new(big.Int).SetBytes(sig.R.Bytes()))
			e.Sub(sig.S, e).Mod(e, n)
			nonce := e.FillBytes(make([]byte, (n.BitLen()+7)/8))
			signed, err := dstu4145.Sign(bytes.NewReader(nonce), key, digest)
			require.NoError(t, err)
			require.True(t, signed.R.Equal(sig.R))
			require.Equal(t, sig.S, signed.S)
			// Change a retained low bit: high hash bits are truncated on small curves.
			digest[len(digest)-1] ^= 1
			require.False(t, dstu4145.Verify(pub, digest, sig))
		})
	}
}
