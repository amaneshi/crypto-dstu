package kalyna

import (
	"bytes"
	"crypto/cipher"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompleteCFBMessageCryptoniteReference(t *testing.T) {
	key := mustHex("1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100")
	iv := mustHex("3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A29282726252423222120")
	input := mustHex("7758A939DD6BD00CAF9153E5A5D5A66129105CA1EA54A97C06FA4A40960A068F61C3E424DE950151AC46879D84A3BCC24EC8FB69008DAF016EF9832FFD3DB39D02185FDB782DC28EAC27B35179FCA40640")
	expected := mustHex("9F9E9D9C9B9A999897969594939291908F8E8D8C8B8A898887868584838281807F7E7D7C7B7A797877767574737271706F6E6D6C6B6A696867666564636261605F5E5D5C5B5A595857565554535251504F")
	actual, err := EncryptCFB(key, iv, input)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	actual, err = DecryptCFB(key, iv, expected)
	require.NoError(t, err)
	require.Equal(t, input, actual)
}

func TestCompleteOFBMatchesIndependentMode(t *testing.T) {
	key, iv := bytes.Repeat([]byte{0x53}, 32), bytes.Repeat([]byte{0x49}, 32)
	for _, length := range []int{0, 1, 31, 32, 33, 63, 64, 65, 129} {
		input := bytes.Repeat([]byte{0xa5}, length)
		block, err := NewCipher256_256(key)
		require.NoError(t, err)
		reference := cipher.NewOFB(block, iv)
		expected := make([]byte, length)
		reference.XORKeyStream(expected, input)
		actual, err := CryptOFB(key, iv, input)
		require.NoError(t, err)
		require.Equal(t, expected, actual)
		actual, err = CryptOFB(key, iv, actual)
		require.NoError(t, err)
		require.Equal(t, input, actual)
	}
	_, err := CryptOFB(key, iv[:31], []byte("data"))
	require.Error(t, err)
	_, err = EncryptCFB(key[:31], iv, []byte("data"))
	require.Error(t, err)
}
