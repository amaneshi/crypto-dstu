package kupyna

import (
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/require"
)

// Keep the original byte-wise field calculation as an independent oracle for
// the packed MDS implementation. It deliberately uses no packed operations.
func referenceMultiplyGF(x, y byte) byte {
	var result byte
	for range 8 {
		if y&1 != 0 {
			result ^= x
		}
		high := x & 0x80
		x <<= 1
		if high != 0 {
			x ^= 0x1d
		}
		y >>= 1
	}
	return result
}

func referenceMixColumn(input [rows]byte) (output [rows]byte) {
	for row := range rows {
		for col := range rows {
			output[row] ^= referenceMultiplyGF(input[col], mdsMatrix[row][col])
		}
	}
	return output
}

func TestPackedMDSMatchesReference(t *testing.T) {
	// Exhaust every byte value in every input lane. Both transformations are
	// linear, so these cases also cover all combinations of basis vectors.
	for lane := range rows {
		for value := range 256 {
			var input [rows]byte
			input[lane] = byte(value)
			state := [][rows]byte{input}
			mixColumns(state)
			require.Equal(t, referenceMixColumn(input), state[0], "lane=%d value=%d", lane, value)
		}
	}
	rng := rand.New(rand.NewPCG(0x7564, 0x4145))
	for _, cols := range []int{nb512, nb1024} {
		for range 100 {
			state := make([][rows]byte, cols)
			expected := make([][rows]byte, cols)
			for col := range state {
				for row := range rows {
					state[col][row] = byte(rng.Uint32())
				}
				expected[col] = referenceMixColumn(state[col])
			}
			mixColumns(state)
			require.Equal(t, expected, state)
		}
	}
}

func TestShiftBytesMatchesReference(t *testing.T) {
	for _, cols := range []int{nb512, nb1024} {
		original := make([][rows]byte, cols)
		expected := make([][rows]byte, cols)
		for col := range original {
			for row := range rows {
				original[col][row] = byte(col*rows + row)
			}
		}
		for row := range rows {
			shift := row
			if cols == nb1024 && row == rows-1 {
				shift = 11
			}
			for col := range original {
				expected[(col+shift)%cols][row] = original[col][row]
			}
		}
		shiftBytes(original)
		require.Equal(t, expected, original)
	}
}
