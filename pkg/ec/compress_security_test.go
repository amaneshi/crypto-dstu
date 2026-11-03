package ec_test

import (
	"math/big"
	"testing"

	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

func TestExpandNoncanonicalZeroDoesNotPanic(t *testing.T) {
	for _, params := range dstu4145.AllParams() {
		t.Run(params.Name, func(t *testing.T) {
			encoding := []byte{1}
			if params.Curve.IsONB() {
				encoding = new(big.Int).Lsh(big.NewInt(1), uint(params.Curve.M-1)).Bytes()
			}
			point, err := params.Curve.Expand(encoding)
			if params.Curve.A.IsZero() {
				require.Error(t, err)
				require.Nil(t, point)
			} else if err == nil {
				require.True(t, params.Curve.Contains(point))
			}
			zero, err := params.Curve.Expand([]byte{0})
			require.NoError(t, err)
			require.True(t, zero.X.IsZero())
			require.True(t, params.Curve.Contains(zero))
		})
	}
}
