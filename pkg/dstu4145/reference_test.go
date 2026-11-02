package dstu4145

import (
	"encoding/hex"
	"math/big"
	"testing"

	"crypto-dstu/pkg/ec"
	"crypto-dstu/pkg/gf2m"
	"github.com/stretchr/testify/require"
)

// Fixed values from privat-it/cryptonite's utest_dstu4145.c, independent of
// this implementation's signer and verifier.
func TestCryptonitePB257Reference(t *testing.T) {
	le := func(s string) []byte { b, e := hex.DecodeString(s); require.NoError(t, e); return reverseRaw(b) }
	c := ec.DSTU_PB_257()
	key := &PrivateKey{Curve: c, D: new(big.Int).SetBytes(le("4854f9d1eeeaab9516288183f164044ec3cdbd00288856db40b4cdf07dfc140900"))}
	x := le("01799b65a6d2d1cecd08b044d599eecfab8412f599f52ca38ddb431bba38e66c00")
	y := le("e54176a56aaf5e5bea7c7dbbacfbe6ad1c35bf9743cb534d839d62be68bc4c5a01")
	pub := key.Public()
	require.True(t, pub.Q.X.Equal(gf2m.FromBytes(x, c.Words)))
	require.True(t, pub.Q.Y.Equal(gf2m.FromBytes(y, c.Words)))
	require.Equal(t, x, pub.Q.Compress())
	point, err := c.Expand(x)
	require.NoError(t, err)
	require.True(t, point.Equal(pub.Q))
	digest := le("b591f4d5ea42d0005dedf238e8beccc2cb46a944419b6fdd66c57e66c751f683")
	r, _ := hex.DecodeString("ace29a89ec34329abf529d109ca838c26b13cc0e14d8663071da94ab198e2e64")
	s, _ := hex.DecodeString("39b9c25ab0187694ec170221e9135405894bf439c9cefea7f23e4e1a974eca1b")
	raw := append(r, s...)
	sig, err := UnmarshalSignatureRaw(raw, c)
	require.NoError(t, err)
	require.True(t, Verify(pub, digest, sig))
	encoded, err := MarshalSignatureRaw(sig, c)
	require.NoError(t, err)
	require.Equal(t, raw, encoded)
	require.Len(t, encoded, 64)
	_, err = UnmarshalSignatureRaw(append(encoded, 0, 0), c)
	require.Error(t, err)
	sig.R = gf2m.FromBytes(c.N, c.Words)
	require.False(t, Verify(pub, digest, sig))
}

func TestCryptonitePB367Signature(t *testing.T) {
	decode := func(s string) []byte { b, e := hex.DecodeString(s); require.NoError(t, e); return b }
	c := ParamsByName("DSTU_PB_367").Curve
	x := decode("7629f54b547bb74fe086e8f4be65602660ffb61b057176cebec137cad9994e3d3d7decb560bf01ebc47a8afee2af")
	y := decode("24863fb306d78bdc760d15681d678a3e3f95edd5577ffa7eb25bc9d1d9319808ee65e7dc8410bb32eb6407da53ed")
	pub := &PublicKey{Curve: c, Q: ec.NewPoint(c, gf2m.FromBytes(x, c.Words), gf2m.FromBytes(y, c.Words))}
	sig := &Signature{R: gf2m.FromBytes(decode("1f8d88f2894b5789fb09078283b619f8ddd1057551141abb24ada18257936e136b223f10afdce8cb091a2f5f8bbe"), c.Words), S: new(big.Int).SetBytes(decode("1cef3a08267d23bf64647a87dfb116756ff87d365149271d00fbb8947eb1f73fe9e75c63df18cf73f985a313cf32"))}
	require.True(t, Verify(pub, decode("09c9c44277910c9aaee486883a2eb95b7180166ddf73532eeb76edaef52247ff"), sig))
}
