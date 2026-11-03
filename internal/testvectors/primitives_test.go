package testvectors_test

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"os"
	"testing"

	"github.com/amaneshi/crypto-dstu/pkg/gost28147"
	"github.com/amaneshi/crypto-dstu/pkg/gost34311"
	uahmac "github.com/amaneshi/crypto-dstu/pkg/hmac"
	"github.com/amaneshi/crypto-dstu/pkg/kalyna"
	"github.com/amaneshi/crypto-dstu/pkg/kupyna"
	"github.com/stretchr/testify/require"
)

type primitiveVector struct {
	Algorithm, Key, Message, Output string
	BlockSize                       int
}

func referenceVectors(t testing.TB) []primitiveVector {
	t.Helper()
	data, err := os.ReadFile("testdata/cryptonite-primitives.json")
	require.NoError(t, err)
	var fixture struct {
		SourceCommit string
		Vectors      []primitiveVector
	}
	require.NoError(t, json.Unmarshal(data, &fixture))
	require.Equal(t, "3618d340d22e27a6becf97d89c453f8e64068a39", fixture.SourceCommit)
	require.Len(t, fixture.Vectors, 309)
	return fixture.Vectors
}

func decodeHex(t testing.TB, text string) []byte {
	t.Helper()
	value, err := hex.DecodeString(text)
	require.NoError(t, err)
	return value
}

func hashFor(name string, key []byte) hash.Hash {
	switch name {
	case "gost34311":
		return gost34311.New()
	case "kupyna256":
		return kupyna.New256()
	case "kupyna384":
		return kupyna.New384()
	case "kupyna512":
		return kupyna.New512()
	case "kmac256":
		return kupyna.NewKMAC256(key)
	case "kmac384":
		return kupyna.NewKMAC384(key)
	case "kmac512":
		return kupyna.NewKMAC512(key)
	case "hmac-gost34311":
		return uahmac.NewGOST34311(key, nil)
	case "hmac-kupyna256":
		return uahmac.NewKupyna256(key)
	case "hmac-kupyna512":
		return uahmac.NewKupyna512(key)
	default:
		panic("unknown test hash profile")
	}
}

func blockFor(t testing.TB, size int, key []byte) cipher.Block {
	t.Helper()
	var block cipher.Block
	var err error
	switch {
	case size == 8:
		block, err = gost28147.NewCipher(key)
	case size == 16 && len(key) == 16:
		block, err = kalyna.NewCipher128_128(key)
	case size == 16:
		block, err = kalyna.NewCipher128_256(key)
	case size == 32 && len(key) == 32:
		block, err = kalyna.NewCipher256_256(key)
	case size == 32:
		block, err = kalyna.NewCipher256_512(key)
	case size == 64:
		block, err = kalyna.NewCipher512_512(key)
	}
	require.NoError(t, err)
	require.NotNil(t, block)
	return block
}

func TestCryptonitePrimitiveKnownAnswers(t *testing.T) {
	for i, vector := range referenceVectors(t) {
		t.Run(fmt.Sprintf("%s/%d", vector.Algorithm, i), func(t *testing.T) {
			key := decodeHex(t, vector.Key)
			message, expected := decodeHex(t, vector.Message), decodeHex(t, vector.Output)
			switch vector.Algorithm {
			case "gost28147-cfb":
				iv:=key[:8]
				output,err:=gost28147.EncryptCFB(key,iv,message)
				require.NoError(t,err);require.Equal(t,expected,output)
				for _,chunk:=range []int{1,3,7,8,9} {
					block:=blockFor(t,8,key)
					encrypt:=gost28147.NewCFBEncrypter(block,iv)
					decrypt:=gost28147.NewCFBDecrypter(block,iv)
					ciphertext,plain:=make([]byte,len(message)),make([]byte,len(message))
					for offset:=0;offset<len(message);offset+=chunk {
						end:=min(offset+chunk,len(message))
						encrypt.XORKeyStream(ciphertext[offset:end],message[offset:end])
						decrypt.XORKeyStream(plain[offset:end],expected[offset:end])
					}
					require.Equal(t,expected,ciphertext)
					require.True(t,bytes.Equal(message,plain))
				}
			case "kalyna-ecb":
				block := blockFor(t, vector.BlockSize, key)
				output := make([]byte, len(message))
				plain := make([]byte, len(message))
				for offset := 0; offset < len(message); offset += block.BlockSize() {
					block.Encrypt(output[offset:], message[offset:])
					block.Decrypt(plain[offset:], expected[offset:])
				}
				require.Equal(t, expected, output)
				require.Equal(t, message, plain)
			case "gost28147-mac":
				block := blockFor(t, 8, key)
				mac := block.(interface{ MAC([]byte, int) []byte })
				require.Equal(t, expected, mac.MAC(message, 64))
			case "kalyna-cbc", "kalyna-ctr", "kalyna-cfb", "kalyna-ofb":
				block := blockFor(t, vector.BlockSize, key)
				iv := make([]byte, vector.BlockSize)
				for i := range iv {
					iv[i] = byte(i)
				}
				output := make([]byte, len(message))
				if vector.Algorithm == "kalyna-cbc" {
					mode, err := kalyna.NewCBCEncrypter(block, iv)
					require.NoError(t, err)
					mode.CryptBlocks(output, message)
				} else {
					var stream cipher.Stream
					var err error
					switch vector.Algorithm {
					case "kalyna-ctr":
						stream, err = kalyna.NewCTR(block, iv)
					case "kalyna-cfb":
						stream, err = kalyna.NewCFBEncrypter(block, iv)
					case "kalyna-ofb":
						stream, err = kalyna.NewOFB(block, iv)
					}
					require.NoError(t, err)
					stream.XORKeyStream(output, message)
				}
				require.Equal(t, expected, output)
			default:
				for _, chunk := range []int{1, 31, 64, 111, 128, 129} {
					h := hashFor(vector.Algorithm, key)
					for offset := 0; offset < len(message); offset += chunk {
						_, err := h.Write(message[offset:min(offset+chunk, len(message))])
						require.NoError(t, err)
					}
					require.Equal(t, expected, h.Sum(nil), "chunk=%d", chunk)
				}
			}
		})
	}
}

func TestBouncyKMACKeyBoundaries(t *testing.T) {
	data, err := os.ReadFile("testdata/bouncycastle-kmac.json")
	require.NoError(t, err)
	var fixture struct {
		Artifact, JarSHA256 string
		Vectors             []primitiveVector
	}
	require.NoError(t, json.Unmarshal(data, &fixture))
	require.Equal(t, "org.bouncycastle:bcprov-jdk18on:1.86", fixture.Artifact)
	require.Equal(t, "2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f", fixture.JarSHA256)
	require.Len(t, fixture.Vectors, 360)
	for i, vector := range fixture.Vectors {
		t.Run(fmt.Sprintf("%s/%d", vector.Algorithm, i), func(t *testing.T) {
			key, message := decodeHex(t, vector.Key), decodeHex(t, vector.Message)
			h := hashFor(vector.Algorithm, key)
			h.Write(message)
			require.Equal(t, decodeHex(t, vector.Output), h.Sum(nil))
			h.Reset()
			for _, b := range message {
				h.Write([]byte{b})
			}
			require.Equal(t, decodeHex(t, vector.Output), h.Sum(nil))
		})
	}
}
