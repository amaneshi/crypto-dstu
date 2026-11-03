package testvectors_test

import (
	"bytes"
	"crypto/cipher"
	"math/big"
	"testing"

	"github.com/amaneshi/crypto-dstu/pkg/dstu15946"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/amaneshi/crypto-dstu/pkg/gf2m"
	"github.com/amaneshi/crypto-dstu/pkg/gost28147"
	"github.com/amaneshi/crypto-dstu/pkg/kalyna"
	"github.com/stretchr/testify/require"
)

func FuzzPrimitiveHashes(f *testing.F) {
	names := []string{"gost34311", "kupyna256", "kupyna384", "kupyna512", "kmac256", "kmac384", "kmac512", "hmac-gost34311", "hmac-kupyna256", "hmac-kupyna512"}
	for i := range names {
		f.Add(byte(i), []byte("public hash fuzz seed"), []byte("public-key"), uint16(i+1))
	}
	for _, vector := range referenceVectors(f) {
		for i, name := range names {
			if name == vector.Algorithm {
				f.Add(byte(i), decodeHex(f, vector.Message), decodeHex(f, vector.Key), uint16(31))
			}
		}
	}
	f.Fuzz(func(t *testing.T, profile byte, data, key []byte, split uint16) {
		if len(data) > 4096 || len(key) > 256 {
			return
		}
		original, originalKey := bytes.Clone(data), bytes.Clone(key)
		name := names[int(profile)%len(names)]
		whole := hashFor(name, key)
		whole.Write(data)
		expected := whole.Sum(nil)
		stream := hashFor(name, key)
		chunk := 1 + int(split)%129
		for offset := 0; offset < len(data); offset += chunk {
			stream.Write(data[offset:min(offset+chunk, len(data))])
		}
		require.Equal(t, expected, stream.Sum(nil))
		require.Equal(t, append([]byte{0xa5}, expected...), stream.Sum([]byte{0xa5}))
		stream.Reset()
		cut := min(int(split), len(data))
		stream.Write(data[:cut])
		stream.Sum(nil) // Sum must not finalize or mutate the running state.
		stream.Write(data[cut:])
		require.Equal(t, expected, stream.Sum(nil))
		require.Equal(t, original, data)
		require.Equal(t, originalKey, key)
	})
}

func fillPublic(destination, source []byte) {
	for i := range destination {
		if len(source) != 0 {
			destination[i] = source[i%len(source)]
		}
	}
}

func FuzzPrimitiveBlocks(f *testing.F) {
	for i := byte(0); i < 6; i++ {
		f.Add(i, []byte("key"), []byte("block and stream fixture"), uint16(7))
	}
	f.Fuzz(func(t *testing.T, profile byte, material, data []byte, split uint16) {
		if len(material) > 128 || len(data) > 2048 {
			return
		}
		sizes, lengths := []int{8, 16, 16, 32, 32, 64}, []int{32, 16, 32, 32, 64, 64}
		index := int(profile) % len(sizes)
		bs := sizes[index]
		key, input, iv := make([]byte, lengths[index]), make([]byte, bs), make([]byte, bs)
		fillPublic(key, material)
		fillPublic(input, data)
		fillPublic(iv, material)
		block := blockFor(t, bs, key)
		output, plain := make([]byte, bs), make([]byte, bs)
		block.Encrypt(output, input)
		block.Decrypt(plain, output)
		require.Equal(t, input, plain)
		inPlace := bytes.Clone(input)
		block.Encrypt(inPlace, inPlace)
		require.Equal(t, output, inPlace)
		block.Decrypt(inPlace, inPlace)
		require.Equal(t, input, inPlace)
		aligned := data[:len(data)/bs*bs]
		got, expected := make([]byte, len(aligned)), make([]byte, len(aligned))
		cbc, err := kalyna.NewCBCEncrypter(block, iv)
		require.NoError(t, err)
		cbc.CryptBlocks(got, aligned)
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(expected, aligned)
		require.Equal(t, expected, got)
		cbc, err = kalyna.NewCBCDecrypter(block, iv)
		require.NoError(t, err)
		cbc.CryptBlocks(got, got)
		require.True(t, bytes.Equal(aligned, got))
		for _, mode := range []string{"ctr", "cfb", "ofb"} {
			newStream := func() cipher.Stream {
				var stream cipher.Stream
				var err error
				switch mode {
				case "ctr":
					if bs == 8 {
						stream, err = gost28147.NewCTR(block, iv)
					} else {
						stream, err = kalyna.NewCTR(block, iv)
					}
				case "cfb":
					if bs == 8 {
						stream = gost28147.NewCFBEncrypter(block, iv)
					} else {
						stream, err = kalyna.NewCFBEncrypter(block, iv)
					}
				case "ofb":
					stream, err = kalyna.NewOFB(block, iv)
				}
				require.NoError(t, err)
				return stream
			}
			whole, fragmented := make([]byte, len(data)), make([]byte, len(data))
			newStream().XORKeyStream(whole, data)
			stream := newStream()
			chunk := 1 + int(split)%129
			for offset := 0; offset < len(data); offset += chunk {
				end := min(offset+chunk, len(data))
				stream.XORKeyStream(fragmented[offset:end], data[offset:end])
			}
			require.Equal(t, whole, fragmented, mode)
		}
	})
}

func polynomialRemainder(value, modulus *big.Int) *big.Int {
	result := new(big.Int).Set(value)
	for result.BitLen() >= modulus.BitLen() {
		result.Xor(result, new(big.Int).Lsh(modulus, uint(result.BitLen()-modulus.BitLen())))
	}
	return result
}

func polynomialProduct(a, b *big.Int) *big.Int {
	result := new(big.Int)
	for bit := 0; bit < b.BitLen(); bit++ {
		if b.Bit(bit) != 0 {
			result.Xor(result, new(big.Int).Lsh(a, uint(bit)))
		}
	}
	return result
}

func FuzzFieldArithmetic(f *testing.F) {
	for i := range dstu4145.AllParams() {
		f.Add(byte(i), []byte{1, 2, 3}, []byte{4, 5, 6})
	}
	f.Fuzz(func(t *testing.T, profile byte, left, right []byte) {
		if len(left) > 64 || len(right) > 64 {
			return
		}
		params := dstu4145.AllParams()
		curve := params[int(profile)%len(params)].Curve
		modulus := new(big.Int)
		for _, exponent := range curve.ModBits {
			modulus.SetBit(modulus, exponent, 1)
		}
		a, b := polynomialRemainder(new(big.Int).SetBytes(left), modulus), polynomialRemainder(new(big.Int).SetBytes(right), modulus)
		x, y := gf2m.FromBytes(a.Bytes(), curve.Words), gf2m.FromBytes(b.Bytes(), curve.Words)
		expected := polynomialRemainder(polynomialProduct(a, b), modulus)
		require.Equal(t, 0, expected.Cmp(new(big.Int).SetBytes(gf2m.ModMul(x, y, curve.ModBits).Bytes())))
		require.Equal(t, 0, new(big.Int).Xor(a, b).Cmp(new(big.Int).SetBytes(gf2m.Add(x, y).Bytes())))
		require.True(t, gf2m.ModSqr(x, curve.ModBits).Equal(gf2m.ModMul(x, x, curve.ModBits)))
		if !x.IsZero() {
			inverse := gf2m.Inv(x, curve.ModBits)
			product := polynomialRemainder(polynomialProduct(a, new(big.Int).SetBytes(inverse.Bytes())), modulus)
			require.Equal(t, big.NewInt(1), product)
		}
	})
}

func FuzzCurveEncodings(f *testing.F) {
	for i, params := range dstu4145.AllParams() {
		f.Add(byte(i), params.Curve.ScalarBaseMul(big.NewInt(2)).Compress())
		f.Add(byte(i), []byte{0})
		bit := 0
		if params.Curve.IsONB() {
			bit = params.Curve.M - 1
		}
		f.Add(byte(i), new(big.Int).Lsh(big.NewInt(1), uint(bit)).Bytes())
	}
	f.Fuzz(func(t *testing.T, profile byte, encoded []byte) {
		if len(encoded) > 128 {
			return
		}
		params := dstu4145.AllParams()
		curve := params[int(profile)%len(params)].Curve
		original := bytes.Clone(encoded)
		point, err := curve.Expand(encoded)
		require.Equal(t, original, encoded)
		if err != nil {
			require.Nil(t, point)
			return
		}
		require.True(t, curve.Contains(point))
		parsed, err := curve.Expand(point.Compress())
		require.NoError(t, err)
		require.True(t, point.Equal(parsed))
		x, err := curve.EncodeField(point.X)
		require.NoError(t, err)
		x, err = curve.DecodeField(x)
		require.NoError(t, err)
		require.True(t, point.X.Equal(x))
	})
}

func FuzzSignaturesAndAgreement(f *testing.F) {
	for i := range dstu4145.AllParams() {
		f.Add(byte(i), []byte{0}, []byte{})
		curve := dstu4145.AllParams()[i].Curve
		key := &dstu4145.PrivateKey{Curve: curve, D: big.NewInt(2)}
		signature, err := dstu4145.Sign(bytes.NewReader(bytes.Repeat([]byte{0x42}, 256)), key, []byte{1})
		require.NoError(f, err)
		raw, err := dstu4145.MarshalSignatureRaw(signature, curve)
		require.NoError(f, err)
		f.Add(byte(i), []byte{1}, raw)
	}
	f.Fuzz(func(t *testing.T, profile byte, digest, raw []byte) {
		if len(digest) > 64 || len(raw) > 128 {
			return
		}
		params := dstu4145.AllParams()
		curve := params[int(profile)%len(params)].Curve
		// Public candidate-derived scalars vary agreement points while keeping
		// scalar multiplication bounded; all domains have orders above 2^64.
		privateScalar := new(big.Int).SetBytes(digest[:min(len(digest), 8)])
		privateScalar.Add(privateScalar, big.NewInt(1))
		peerScalar := new(big.Int).SetBytes(raw[:min(len(raw), 8)])
		peerScalar.Add(peerScalar, big.NewInt(1))
		key := &dstu4145.PrivateKey{Curve: curve, D: privateScalar}
		peer := &dstu4145.PrivateKey{Curve: curve, D: peerScalar}
		sig, err := dstu4145.Sign(bytes.NewReader(bytes.Repeat([]byte{0x42}, 256)), key, digest)
		if err == nil {
			require.True(t, dstu4145.Verify(key.Public(), digest, sig))
			encoded, err := dstu4145.MarshalSignatureRaw(sig, curve)
			require.NoError(t, err)
			parsed, err := dstu4145.UnmarshalSignatureRaw(encoded, curve)
			require.NoError(t, err)
			require.True(t, dstu4145.Verify(key.Public(), digest, parsed))
			parsed.S = big.NewInt(0)
			require.False(t, dstu4145.Verify(key.Public(), digest, parsed))
		}
		parsed, err := dstu4145.UnmarshalSignatureRaw(raw, curve)
		if err == nil {
			dstu4145.Verify(key.Public(), digest, parsed)
			encoded, err := dstu4145.MarshalSignatureRaw(parsed, curve)
			require.NoError(t, err)
			require.Equal(t, raw, encoded)
		} else {
			require.Nil(t, parsed)
		}
		left, err := dstu15946.SharedSecret(key, peer.Public())
		require.NoError(t, err)
		right, err := dstu15946.SharedSecret(peer, key.Public())
		require.NoError(t, err)
		require.Equal(t, left, right)
		left, err = dstu15946.SharedSecretStandard(key, peer.Public())
		require.NoError(t, err)
		right, err = dstu15946.SharedSecretStandard(peer, key.Public())
		require.NoError(t, err)
		require.Equal(t, left, right)
	})
}

func FuzzCMSKeyWrap(f *testing.F) {
	f.Add([]byte("public CMS wrap seed"), []byte{})
	f.Fuzz(func(t *testing.T, material, arbitrary []byte) {
		if len(material) > 128 || len(arbitrary) > 128 {
			return
		}
		key, cek, iv := make([]byte, 32), make([]byte, 32), make([]byte, 32)
		fillPublic(key, material)
		fillPublic(cek, arbitrary)
		fillPublic(iv, material)
		wrapped, err := kalyna.WrapKey(key, cek, iv)
		require.NoError(t, err)
		plain, err := kalyna.UnwrapKey(key, wrapped)
		require.NoError(t, err)
		require.Equal(t, cek, plain)
		for _, position := range []int{0, 32, 95} {
			bad := bytes.Clone(wrapped)
			bad[position] ^= 1
			plain, err = kalyna.UnwrapKey(key, bad)
			require.Error(t, err)
			require.Nil(t, plain)
		}
		plain, err = kalyna.UnwrapKey(key, arbitrary)
		if err != nil {
			require.Nil(t, plain)
		}
	})
}
