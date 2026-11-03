package kalyna

import (
	"bytes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func kwTestBlock(t *testing.T, bs int, key []byte) cipher.Block {
	t.Helper()
	var b cipher.Block
	var err error
	switch {
	case bs == 16 && len(key) == 16:
		b, err = NewCipher128_128(key)
	case bs == 16:
		b, err = NewCipher128_256(key)
	case bs == 32 && len(key) == 32:
		b, err = NewCipher256_256(key)
	case bs == 32:
		b, err = NewCipher256_512(key)
	case bs == 64:
		b, err = NewCipher512_512(key)
	}
	require.NoError(t, err)
	require.NotNil(t, b)
	return b
}

func TestKWKnownAnswers(t *testing.T) {
	// Public vectors from privat-it/cryptonite, atest_dstu7624.c, kw_data.
	fixture, err := os.ReadFile("testdata/cryptonite-kw.json")
	require.NoError(t, err)
	var vectors []struct {
		Key, Plain, Wrapped string
		BlockSize           int
	}
	require.NoError(t, json.Unmarshal(fixture, &vectors))
	require.Len(t, vectors, 9)
	for i, v := range vectors {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			kw := NewKWEncrypter(kwTestBlock(t, v.BlockSize, mustHex(v.Key)))
			plain, expected := mustHex(v.Plain), mustHex(v.Wrapped)
			var wrapped, recovered []byte
			var err error
			if len(plain)%v.BlockSize == 0 {
				wrapped, err = kw.Wrap(plain)
				require.NoError(t, err)
				recovered, err = kw.Unwrap(expected)
			} else {
				wrapped, err = kw.WrapPadded(plain)
				require.NoError(t, err)
				recovered, err = kw.UnwrapPadded(expected, len(plain))
			}
			require.NoError(t, err)
			require.Equal(t, expected, wrapped)
			require.Equal(t, plain, recovered)
		})
	}
}

func TestKWLargeCounterKnownAnswers(t *testing.T) {
	t.Parallel()
	fixture, err := os.ReadFile("testdata/bouncycastle-kw-large.json")
	require.NoError(t, err)
	var reference struct {
		Artifact, JarSHA256 string
		Vectors             []struct {
			Name, Key, Plain, Wrapped string
			BlockSize, Rounds         int
		}
	}
	require.NoError(t, json.Unmarshal(fixture, &reference))
	require.Equal(t, "org.bouncycastle:bcprov-jdk18on:1.86", reference.Artifact)
	require.Equal(t, "2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f", reference.JarSHA256)
	require.Len(t, reference.Vectors, 15)
	for _, v := range reference.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			key, plain, expected := mustHex(v.Key), mustHex(v.Plain), mustHex(v.Wrapped)
			require.Len(t, expected, len(plain)+v.BlockSize)
			require.Equal(t, v.Rounds, 6*(len(expected)/(v.BlockSize/2)-1))
			require.Contains(t, []int{246, 258, 270}, v.Rounds)
			t.Run("wrap", func(t *testing.T) {
				original := bytes.Clone(plain)
				kw := NewKWEncrypter(kwTestBlock(t, v.BlockSize, key))
				wrapped, err := kw.Wrap(plain)
				require.NoError(t, err)
				require.Equal(t, expected, wrapped)
				require.Equal(t, original, plain)
			})
			t.Run("unwrap", func(t *testing.T) {
				original := bytes.Clone(expected)
				kw := NewKWDecrypter(kwTestBlock(t, v.BlockSize, key))
				recovered, err := kw.Unwrap(expected)
				require.NoError(t, err)
				require.Equal(t, plain, recovered)
				require.Equal(t, original, expected)
			})
			t.Run("reject", func(t *testing.T) {
				wrongKey := bytes.Clone(key)
				wrongKey[0] ^= 0x80
				wrong := NewKWDecrypter(kwTestBlock(t, v.BlockSize, wrongKey))
				recovered, err := wrong.Unwrap(expected)
				require.Error(t, err)
				require.Nil(t, recovered)
				kw := NewKWDecrypter(kwTestBlock(t, v.BlockSize, key))
				for _, offset := range []int{0, len(expected) / 2, len(expected) - 1} {
					corrupted := bytes.Clone(expected)
					corrupted[offset] ^= 1
					recovered, err := kw.Unwrap(corrupted)
					require.Error(t, err, "corrupted byte %d", offset)
					require.Nil(t, recovered)
				}
			})
		})
	}
}

func TestKWIntegrityAndLengths(t *testing.T) {
	for _, bs := range []int{16, 32, 64} {
		t.Run(fmt.Sprint(bs), func(t *testing.T) {
			kw := NewKWEncrypter(kwTestBlock(t, bs, bytes.Repeat([]byte{0x57}, bs)))
			wrong := NewKWDecrypter(kwTestBlock(t, bs, bytes.Repeat([]byte{0x58}, bs)))
			for _, size := range []int{0, bs, 2 * bs, 32 * bs} {
				plain := make([]byte, size) // Preserve all-zero keys and trailing zeros.
				if size > 0 {
					plain[0] = 0x80
				}
				wrapped, err := kw.Wrap(plain)
				require.NoError(t, err)
				require.Len(t, wrapped, size+bs)
				recovered, err := kw.Unwrap(wrapped)
				require.NoError(t, err)
				require.Equal(t, plain, recovered)
				recovered, err = wrong.Unwrap(wrapped)
				require.Error(t, err)
				require.Nil(t, recovered)
				if size == bs {
					for i := range wrapped {
						bad := bytes.Clone(wrapped)
						bad[i] ^= 1
						recovered, err = kw.Unwrap(bad)
						require.Error(t, err, "byte %d", i)
						require.Nil(t, recovered)
					}
				}
			}
			for size := 0; size < 3*bs; size++ {
				if size >= bs && size%bs == 0 {
					continue
				}
				p, err := kw.Unwrap(make([]byte, size))
				require.Error(t, err)
				require.Nil(t, p)
			}
			for size := 1; size < 2*bs; size++ {
				if size%bs == 0 {
					continue
				}
				plain := bytes.Repeat([]byte{0x80}, size)
				p, err := kw.Wrap(plain)
				require.Error(t, err)
				require.Nil(t, p)
				wrapped, err := kw.WrapPadded(plain)
				require.NoError(t, err)
				p, err = kw.UnwrapPadded(wrapped, size)
				require.NoError(t, err)
				require.Equal(t, plain, p)
				p, err = kw.UnwrapPadded(wrapped, size+1)
				require.Error(t, err)
				require.Nil(t, p)
			}
		})
	}
}

func TestKWRejectsMalformedPadding(t *testing.T) {
	kw := NewKWEncrypter(kwTestBlock(t, 16, make([]byte, 16)))
	canonical := kwPad([]byte{0x42}, 16)
	for i := 1; i < len(canonical); i++ {
		bad := bytes.Clone(canonical)
		bad[i] ^= 1
		wrapped, err := kw.Wrap(bad) // Valid integrity, invalid trailer or padding.
		require.NoError(t, err)
		p, err := kw.UnwrapPadded(wrapped, 1)
		require.Error(t, err)
		require.Nil(t, p)
	}
}

func FuzzKWUnwrap(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 32))
	b, _ := NewCipher128_128(make([]byte, 16))
	kw := NewKWDecrypter(b)
	valid, _ := kw.Wrap([]byte{})
	f.Add(valid)
	valid, _ = kw.Wrap(make([]byte, 16))
	f.Add(valid)
	f.Fuzz(func(t *testing.T, src []byte) {
		if len(src) > 4096 {
			t.Skip()
		}
		p, err := kw.Unwrap(src)
		if err != nil {
			require.Nil(t, p)
			return
		}
		wrapped, err := kw.Wrap(p)
		require.NoError(t, err)
		require.Equal(t, src, wrapped)
	})
}
