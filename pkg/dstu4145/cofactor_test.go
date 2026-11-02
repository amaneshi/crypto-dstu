package dstu4145

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// Known subgroup orders and cofactors must place the group cardinality inside
// Hasse's interval. Comparing squared integers avoids rounding sqrt(2^m).
func TestStandardDomainCofactors(t *testing.T) {
	for _, params := range AllParams() {
		t.Run(params.Name, func(t *testing.T) {
			curve := params.Curve
			q := new(big.Int).Lsh(big.NewInt(1), uint(curve.M))
			cardinality := new(big.Int).Mul(new(big.Int).SetBytes(curve.N), big.NewInt(int64(curve.Cofactor)))
			difference := new(big.Int).Sub(cardinality, new(big.Int).Add(q, big.NewInt(1)))
			difference.Mul(difference, difference)
			bound := new(big.Int).Lsh(q, 2)
			require.LessOrEqual(t, difference.Cmp(bound), 0, "subgroup order times cofactor violates the cardinality bound")
		})
	}
}
