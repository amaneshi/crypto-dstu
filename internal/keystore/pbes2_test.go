package keystore

import (
	"bytes"
	"encoding/asn1"
	"testing"

	"crypto-dstu/pkg/kalyna"
	"github.com/stretchr/testify/require"
)

func TestKalynaPBES2PaddingAndParameters(t *testing.T) {
	kdf := pbkdf2Params{Salt: []byte("public test salt"), Iterations: 2, PRF: algorithmIdentifier{Algorithm: oidKupynaKMAC256}}
	password := []byte("test")
	key, err := pbkdf2ForPRF(password, kdf, 32)
	require.NoError(t, err)
	iv := make([]byte, 32)
	parameters, err := asn1.Marshal(struct{ IV []byte }{iv})
	require.NoError(t, err)
	p2 := pbes2Params{EncScheme: algorithmIdentifier{Algorithm: oidKalyna256CBC, Parameters: asn1.RawValue{FullBytes: parameters}}}
	for _, tc := range []struct {
		name   string
		padded []byte
		fail   bool
	}{
		{"one byte padding", append(bytes.Repeat([]byte{0x42}, 31), 1), false},
		{"full block padding", bytes.Repeat([]byte{32}, 32), false},
		{"zero padding", make([]byte, 32), true},
		{"oversized padding", bytes.Repeat([]byte{33}, 32), true},
		{"inconsistent padding", append(bytes.Repeat([]byte{0x42}, 31), 2), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			block, err := kalyna.NewCipher256_256(key)
			require.NoError(t, err)
			mode, err := kalyna.NewCBCEncrypter(block, iv)
			require.NoError(t, err)
			encrypted := make([]byte, len(tc.padded))
			mode.CryptBlocks(encrypted, tc.padded)
			plaintext, err := decryptPBES2Data(p2, kdf, encrypted, password)
			if tc.fail {
				require.Error(t, err)
				require.Nil(t, plaintext)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.padded[:len(tc.padded)-int(tc.padded[len(tc.padded)-1])], plaintext)
			}
		})
	}
	for _, ciphertext := range [][]byte{nil, make([]byte, 31), make([]byte, 33)} {
		_, err := decryptPBES2Data(p2, kdf, ciphertext, password)
		require.Error(t, err)
	}
	for _, params := range [][]byte{nil, {4, 1, 0}, append(parameters, 5, 0)} {
		p2.EncScheme.Parameters.FullBytes = params
		_, err := decryptPBES2Data(p2, kdf, make([]byte, 32), password)
		require.Error(t, err)
	}
}

func TestPBKDF2RejectsUnsupportedProfiles(t *testing.T) {
	valid := pbkdf2Params{Salt: []byte("salt"), Iterations: 1, PRF: algorithmIdentifier{Algorithm: oidKupynaKMAC256}}
	for _, tc := range []struct {
		name     string
		change   func(*pbkdf2Params)
		password []byte
	}{
		{"zero iterations", func(p *pbkdf2Params) { p.Iterations = 0 }, nil},
		{"excessive iterations", func(p *pbkdf2Params) { p.Iterations = 1_000_001 }, nil},
		{"empty salt", func(p *pbkdf2Params) { p.Salt = nil }, nil},
		{"wrong key length", func(p *pbkdf2Params) { p.KeyLength = 16 }, nil},
		{"unknown PRF", func(p *pbkdf2Params) { p.PRF.Algorithm = asn1.ObjectIdentifier{1, 2, 3} }, nil},
		{"PRF parameters", func(p *pbkdf2Params) { p.PRF.Parameters.FullBytes = []byte{4, 0} }, nil},
		{"long password", func(p *pbkdf2Params) {}, make([]byte, 33)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := valid
			tc.change(&p)
			key, err := pbkdf2ForPRF(tc.password, p, 32)
			require.Error(t, err)
			require.Nil(t, key)
		})
	}
}
