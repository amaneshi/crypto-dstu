package kupyna

// state is stored as [columns][rows]byte, i.e. column-major order matching the reference impl.
// state[col][row]

// multiplyGF multiplies two bytes in GF(2^8) with reduction polynomial 0x11d.
func multiplyGF(x, y byte) byte {
	var r byte
	for i := 0; i < 8; i++ {
		if y&1 == 1 {
			r ^= x
		}
		hbit := x & 0x80
		x <<= 1
		if hbit != 0 {
			x ^= 0x1d // low byte of reductionPoly 0x011d
		}
		y >>= 1
	}
	return r
}

// subBytes applies S-box substitution: column j uses sbox[row % 4].
func subBytes(state [][rows]byte) {
	for j := range state {
		for i := 0; i < rows; i++ {
			state[j][i] = sboxes[i%4][state[j][i]]
		}
	}
}

// shiftBytes cyclically shifts each row of the state.
// For 8 columns (512-bit state): shift for row i = i.
// For 16 columns (1024-bit state): shifts = [0,1,2,3,4,5,6,11].
func shiftBytes(state [][rows]byte) {
	cols := len(state)
	temp := make([]byte, cols)
	for i := 0; i < rows; i++ {
		shift := i
		if cols == nb1024 && i == rows-1 {
			shift = 11
		}
		for j := 0; j < cols; j++ {
			temp[(j+shift)%cols] = state[j][i]
		}
		for j := 0; j < cols; j++ {
			state[j][i] = temp[j]
		}
	}
}

// mixColumns multiplies each column by the MDS matrix in GF(2^8).
func mixColumns(state [][rows]byte) {
	var result [rows]byte
	for col := range state {
		for row := 0; row < rows; row++ {
			var product byte
			for b := 0; b < rows; b++ {
				product ^= multiplyGF(state[col][b], mdsMatrix[row][b])
			}
			result[row] = product
		}
		state[col] = result
	}
}

// addRoundConstantP adds round constant for permutation P (T⊕).
// state[col][0] ^= (col * 0x10) ^ round
func addRoundConstantP(state [][rows]byte, round int) {
	for i := range state {
		state[i][0] ^= byte((i * 0x10) ^ round)
	}
}

// addRoundConstantQ adds round constant for permutation Q (T+).
// Adds (0x00F0F0F0F0F0F0F3 ^ (((cols-col-1)*0x10 ^ round) << 56)) to each column as uint64 LE.
func addRoundConstantQ(state [][rows]byte, round int) {
	cols := len(state)
	for j := range state {
		// Build the 8-byte constant as little-endian uint64
		constant := uint64(0x00F0F0F0F0F0F0F3) ^ (uint64((cols-j-1)*0x10^round) << 56)
		// Add to column interpreted as little-endian uint64
		var val uint64
		for b := 0; b < rows; b++ {
			val |= uint64(state[j][b]) << (uint(b) * 8)
		}
		val += constant
		for b := 0; b < rows; b++ {
			state[j][b] = byte(val >> (uint(b) * 8))
		}
	}
}

// permP applies permutation P (used with h⊕m block): AddConstantP → SubBytes → ShiftBytes → MixColumns.
func permP(state [][rows]byte, rounds int) {
	for r := 0; r < rounds; r++ {
		addRoundConstantP(state, r)
		subBytes(state)
		shiftBytes(state)
		mixColumns(state)
	}
}

// permQ applies permutation Q (used with m block): AddConstantQ → SubBytes → ShiftBytes → MixColumns.
func permQ(state [][rows]byte, rounds int) {
	for r := 0; r < rounds; r++ {
		addRoundConstantQ(state, r)
		subBytes(state)
		shiftBytes(state)
		mixColumns(state)
	}
}

// compress processes one block using the Davies-Meyer construction:
// h = P(h⊕m) ⊕ Q(m) ⊕ h
func compress(h [][rows]byte, block []byte, rounds int) {
	cols := len(h)
	// Build temp1 = h ⊕ m, temp2 = m
	temp1 := make([][rows]byte, cols)
	temp2 := make([][rows]byte, cols)
	for j := 0; j < cols; j++ {
		for i := 0; i < rows; i++ {
			b := block[j*rows+i]
			temp1[j][i] = h[j][i] ^ b
			temp2[j][i] = b
		}
	}
	permP(temp1, rounds)
	permQ(temp2, rounds)
	for j := 0; j < cols; j++ {
		for i := 0; i < rows; i++ {
			h[j][i] ^= temp1[j][i] ^ temp2[j][i]
		}
	}
}

// outputTransform applies the final output transformation: h = P(h) ⊕ h.
func outputTransform(h [][rows]byte, rounds int) {
	cols := len(h)
	temp := make([][rows]byte, cols)
	for j := 0; j < cols; j++ {
		temp[j] = h[j]
	}
	permP(temp, rounds)
	for j := 0; j < cols; j++ {
		for i := 0; i < rows; i++ {
			h[j][i] ^= temp[j][i]
		}
	}
}

// stateToBytes converts column-major state to a flat byte slice (column-major order).
func stateToBytes(state [][rows]byte) []byte {
	out := make([]byte, len(state)*rows)
	for j := range state {
		for i := 0; i < rows; i++ {
			out[j*rows+i] = state[j][i]
		}
	}
	return out
}

// bytesToState converts a flat byte slice to column-major state.
func bytesToState(b []byte, cols int) [][rows]byte {
	state := make([][rows]byte, cols)
	for j := 0; j < cols; j++ {
		for i := 0; i < rows; i++ {
			state[j][i] = b[j*rows+i]
		}
	}
	return state
}
