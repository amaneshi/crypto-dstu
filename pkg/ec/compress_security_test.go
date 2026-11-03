package ec_test

import (
	"testing"

	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

func TestExpandNoncanonicalZeroDoesNotPanic(t *testing.T) {
	for _, params := range dstu4145.AllParams() {
		t.Run(params.Name, func(t *testing.T) {
			point, err := params.Curve.Expand([]byte{1})
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
