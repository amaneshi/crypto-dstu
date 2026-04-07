package kalyna

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// uint64sToBytes converts a slice of uint64 (little-endian) to bytes.
func uint64sToBytes(words []uint64) []byte {
	b := make([]byte, len(words)*8)
	for i, w := range words {
		binary.LittleEndian.PutUint64(b[i*8:], w)
	}
	return b
}

// Reference test vectors from Roman-Oliynykov/Kalyna-reference main.c.
var encryptVectors = []struct {
	name string
	new  func([]byte) (interface {
		Encrypt(dst, src []byte)
		Decrypt(dst, src []byte)
		BlockSize() int
	}, error)
	pt  []uint64
	key []uint64
	ct  []uint64
}{
	{
		"128/128",
		func(k []byte) (interface {
			Encrypt(dst, src []byte)
			Decrypt(dst, src []byte)
			BlockSize() int
		}, error) {
			return NewCipher128_128(k)
		},
		[]uint64{0x1716151413121110, 0x1f1e1d1c1b1a1918},
		[]uint64{0x0706050403020100, 0x0f0e0d0c0b0a0908},
		[]uint64{0x20ac9b777d1cbf81, 0x06add2b439eac9e1},
	},
	{
		"128/256",
		func(k []byte) (interface {
			Encrypt(dst, src []byte)
			Decrypt(dst, src []byte)
			BlockSize() int
		}, error) {
			return NewCipher128_256(k)
		},
		[]uint64{0x2726252423222120, 0x2f2e2d2c2b2a2928},
		[]uint64{0x0706050403020100, 0x0f0e0d0c0b0a0908, 0x1716151413121110, 0x1f1e1d1c1b1a1918},
		[]uint64{0x8a150010093eec58, 0x144f336f16f74811},
	},
	{
		"256/256",
		func(k []byte) (interface {
			Encrypt(dst, src []byte)
			Decrypt(dst, src []byte)
			BlockSize() int
		}, error) {
			return NewCipher256_256(k)
		},
		[]uint64{0x2726252423222120, 0x2f2e2d2c2b2a2928, 0x3736353433323130, 0x3f3e3d3c3b3a3938},
		[]uint64{0x0706050403020100, 0x0f0e0d0c0b0a0908, 0x1716151413121110, 0x1f1e1d1c1b1a1918},
		[]uint64{0x3521c90e573d6ef6, 0x8c2abddc23e3daae, 0x5a0d6a20ec6339a0, 0x2cd97f61245c3888},
	},
	{
		"256/512",
		func(k []byte) (interface {
			Encrypt(dst, src []byte)
			Decrypt(dst, src []byte)
			BlockSize() int
		}, error) {
			return NewCipher256_512(k)
		},
		[]uint64{0x4746454443424140, 0x4f4e4d4c4b4a4948, 0x5756555453525150, 0x5f5e5d5c5b5a5958},
		[]uint64{
			0x0706050403020100, 0x0f0e0d0c0b0a0908, 0x1716151413121110, 0x1f1e1d1c1b1a1918,
			0x2726252423222120, 0x2f2e2d2c2b2a2928, 0x3736353433323130, 0x3f3e3d3c3b3a3938,
		},
		[]uint64{0x7ab6b7e6e9906960, 0xb76822d793d8d64b, 0x02e1d73c3cc8028e, 0xd95dfefda8742efd},
	},
	{
		"512/512",
		func(k []byte) (interface {
			Encrypt(dst, src []byte)
			Decrypt(dst, src []byte)
			BlockSize() int
		}, error) {
			return NewCipher512_512(k)
		},
		[]uint64{
			0x4746454443424140, 0x4f4e4d4c4b4a4948, 0x5756555453525150, 0x5f5e5d5c5b5a5958,
			0x6766656463626160, 0x6f6e6d6c6b6a6968, 0x7776757473727170, 0x7f7e7d7c7b7a7978,
		},
		[]uint64{
			0x0706050403020100, 0x0f0e0d0c0b0a0908, 0x1716151413121110, 0x1f1e1d1c1b1a1918,
			0x2726252423222120, 0x2f2e2d2c2b2a2928, 0x3736353433323130, 0x3f3e3d3c3b3a3938,
		},
		[]uint64{
			0x6a351c811be3264a, 0x1a239605cad61da6, 0xa1f347aa5483ba67, 0xb856eb20c3ee1d3e,
			0x66ab5b1717f4d095, 0x6cc815bb34f1d62f, 0xb7fe6e85266a90cb, 0xd9d90d947264bcc5,
		},
	},
}

func TestKalynaEncrypt(t *testing.T) {
	for _, v := range encryptVectors {
		t.Run(v.name, func(t *testing.T) {
			keyBytes := uint64sToBytes(v.key)
			ptBytes := uint64sToBytes(v.pt)
			ctBytes := uint64sToBytes(v.ct)

			c, err := v.new(keyBytes)
			require.NoError(t, err, "NewCipher")

			got := make([]byte, len(ptBytes))
			c.Encrypt(got, ptBytes)

			require.Equal(t, hex.EncodeToString(ctBytes), hex.EncodeToString(got), "Encrypt mismatch")
		})
	}
}

func TestKalynaDecrypt(t *testing.T) {
	// Decrypt test vectors from main.c (separate decrypt vectors, reversed keys/ct)
	type decVec struct {
		name string
		new  func([]byte) (interface {
			Encrypt(dst, src []byte)
			Decrypt(dst, src []byte)
			BlockSize() int
		}, error)
		ct  []uint64
		key []uint64
		pt  []uint64
	}
	decryptVectors := []decVec{
		{
			"128/128",
			func(k []byte) (interface {
				Encrypt(dst, src []byte)
				Decrypt(dst, src []byte)
				BlockSize() int
			}, error) {
				return NewCipher128_128(k)
			},
			[]uint64{0x18191a1b1c1d1e1f, 0x1011121314151617},
			[]uint64{0x08090a0b0c0d0e0f, 0x0001020304050607},
			[]uint64{0x84c70c472bef9172, 0xd7da733930c2096f},
		},
		{
			"128/256",
			func(k []byte) (interface {
				Encrypt(dst, src []byte)
				Decrypt(dst, src []byte)
				BlockSize() int
			}, error) {
				return NewCipher128_256(k)
			},
			[]uint64{0x28292a2b2c2d2e2f, 0x2021222324252627},
			[]uint64{0x18191a1b1c1d1e1f, 0x1011121314151617, 0x08090a0b0c0d0e0f, 0x0001020304050607},
			[]uint64{0xe1dffdce56b46df3, 0x96d9ca30705f5bb4},
		},
		{
			"256/256",
			func(k []byte) (interface {
				Encrypt(dst, src []byte)
				Decrypt(dst, src []byte)
				BlockSize() int
			}, error) {
				return NewCipher256_256(k)
			},
			[]uint64{0x38393a3b3c3d3e3f, 0x3031323334353637, 0x28292a2b2c2d2e2f, 0x2021222324252627},
			[]uint64{0x18191a1b1c1d1e1f, 0x1011121314151617, 0x08090a0b0c0d0e0f, 0x0001020304050607},
			[]uint64{0x864e67967823c57f, 0xa34b8b3fb0e9c103, 0xd3c33f2c597c5bab, 0xe30fb28625d1ed61},
		},
		{
			"256/512",
			func(k []byte) (interface {
				Encrypt(dst, src []byte)
				Decrypt(dst, src []byte)
				BlockSize() int
			}, error) {
				return NewCipher256_512(k)
			},
			[]uint64{0x58595a5b5c5d5e5f, 0x5051525354555657, 0x48494a4b4c4d4e4f, 0x4041424344454647},
			[]uint64{
				0x38393a3b3c3d3e3f, 0x3031323334353637, 0x28292a2b2c2d2e2f, 0x2021222324252627,
				0x18191a1b1c1d1e1f, 0x1011121314151617, 0x08090a0b0c0d0e0f, 0x0001020304050607,
			},
			[]uint64{0x82d4da67277a3118, 0x078d78a1b907cdbc, 0x97845f9e1898705e, 0xe06aba796d910b2d},
		},
	}

	for _, v := range decryptVectors {
		t.Run(v.name, func(t *testing.T) {
			keyBytes := uint64sToBytes(v.key)
			ctBytes := uint64sToBytes(v.ct)
			ptBytes := uint64sToBytes(v.pt)

			c, err := v.new(keyBytes)
			require.NoError(t, err, "NewCipher")

			got := make([]byte, len(ctBytes))
			c.Decrypt(got, ctBytes)

			require.Equal(t, hex.EncodeToString(ptBytes), hex.EncodeToString(got), "Decrypt mismatch")
		})
	}
}

func TestKalynaRoundtrip(t *testing.T) {
	for _, v := range encryptVectors {
		t.Run(v.name, func(t *testing.T) {
			keyBytes := uint64sToBytes(v.key)
			ptBytes := uint64sToBytes(v.pt)

			c, err := v.new(keyBytes)
			require.NoError(t, err, "NewCipher")

			ct := make([]byte, len(ptBytes))
			c.Encrypt(ct, ptBytes)

			got := make([]byte, len(ct))
			c.Decrypt(got, ct)

			require.Equal(t, hex.EncodeToString(ptBytes), hex.EncodeToString(got), "Roundtrip mismatch")
		})
	}
}
