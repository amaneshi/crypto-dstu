package keystore

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"testing"

	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

func TestMarshalKey6Kalyna(t *testing.T) {
	key, err := dstu4145.GenerateKey(dstu4145.ParamsByName("DSTU_PB_257").Curve)
	require.NoError(t, err)
	raw, err := MarshalRawKey(key)
	require.NoError(t, err)
	salt, iv := bytes.Repeat([]byte{0x53}, 32), bytes.Repeat([]byte{0x49}, 32)
	for _, password := range []string{"test", "Тест", string(bytes.Repeat([]byte{'P'}, 32))} {
		t.Run(fmt.Sprintf("%d bytes", len(password)), func(t *testing.T) {
			encoded, err := MarshalKey6Kalyna(raw, password, salt, 2, iv)
			require.NoError(t, err)
			read, err := ParseKey6(encoded, password)
			require.NoError(t, err)
			require.Equal(t, key.D, read.D)
			var epki encryptedPrivateKeyInfo
			_, err = asn1.Unmarshal(encoded, &epki)
			require.NoError(t, err)
			p, kdf, err := parsePBES2Parameters(epki.Algorithm)
			require.NoError(t, err)
			require.Equal(t, oidKalyna256CBC, p.EncScheme.Algorithm)
			require.Equal(t, oidKupynaKMAC256, kdf.PRF.Algorithm)
			require.Equal(t, salt, kdf.Salt)
			require.Equal(t, 2, kdf.Iterations)
			read, err = ParseKey6(encoded, "wrong")
			require.Error(t, err)
			require.Nil(t, read)
		})
	}
	for _, size := range []int{1, 31, 32, 33, 64} {
		t.Run(fmt.Sprintf("padding %d", size), func(t *testing.T) {
			plain := bytes.Repeat([]byte{0x42}, size)
			encoded, err := MarshalKey6Kalyna(plain, "test", salt, 2, iv)
			require.NoError(t, err)
			var epki encryptedPrivateKeyInfo
			_, err = asn1.Unmarshal(encoded, &epki)
			require.NoError(t, err)
			require.Len(t, epki.EncryptedData, (size/32+1)*32)
			p, kdf, err := parsePBES2Parameters(epki.Algorithm)
			require.NoError(t, err)
			read, err := decryptPBES2Data(p, kdf, epki.EncryptedData, []byte("test"))
			require.NoError(t, err)
			require.Equal(t, plain, read)
		})
	}
}

func TestMarshalKey6KalynaRejectsInvalidOptions(t *testing.T) {
	for _, tc := range []struct {
		name, password string
		salt, iv, raw  []byte
		iterations     int
	}{
		{"empty salt", "test", nil, make([]byte, 32), []byte{1}, 1},
		{"short IV", "test", []byte{1}, make([]byte, 31), []byte{1}, 1},
		{"zero iterations", "test", []byte{1}, make([]byte, 32), []byte{1}, 0},
		{"excessive iterations", "test", []byte{1}, make([]byte, 32), []byte{1}, 1000001},
		{"long password", string(bytes.Repeat([]byte{'P'}, 33)), []byte{1}, make([]byte, 32), []byte{1}, 1},
		{"empty key", "test", []byte{1}, make([]byte, 32), nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := MarshalKey6Kalyna(tc.raw, tc.password, tc.salt, tc.iterations, tc.iv)
			require.Error(t, err)
			require.Nil(t, out)
		})
	}
}
