package kalyna

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCMSWrapIntegrity(t *testing.T) {
	kek := bytes.Repeat([]byte{0x53}, 32)
	cek := make([]byte, 32)
	for i := range cek {
		cek[i] = byte(i)
	}
	cek[31] = 0
	iv := bytes.Repeat([]byte{0x49}, 32)
	wrapped, err := WrapKey(kek, cek, iv)
	require.NoError(t, err)
	require.Len(t, wrapped, 96)
	unwrapped, err := UnwrapKey(kek, wrapped)
	require.NoError(t, err)
	require.Equal(t, cek, unwrapped)
	for i := range wrapped {
		corrupt := bytes.Clone(wrapped)
		corrupt[i] ^= 1
		plaintext, err := UnwrapKey(kek, corrupt)
		require.Error(t, err, "byte=%d", i)
		require.Nil(t, plaintext)
	}
	plaintext, err := UnwrapKey(bytes.Repeat([]byte{0x54}, 32), wrapped)
	require.Error(t, err)
	require.Nil(t, plaintext)
	for _, length := range []int{0, 31, 32, 64, 95, 97} {
		plaintext, err := UnwrapKey(kek, make([]byte, length))
		require.Error(t, err)
		require.Nil(t, plaintext)
	}
	_, err = WrapKey(kek, cek, iv[:31])
	require.Error(t, err)
	_, err = WrapKey(kek, cek[:31], iv)
	require.Error(t, err)
	_, err = WrapKey(kek[:31], cek, iv)
	require.Error(t, err)
}
