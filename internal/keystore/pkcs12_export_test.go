package keystore

import (
	"bytes"
	"encoding/asn1"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/stretchr/testify/require"
)

func exportedBags(t *testing.T, data []byte) (pfxASN, []safeBag) {
	t.Helper()
	var pfx pfxASN
	_, err := asn1.Unmarshal(data, &pfx)
	require.NoError(t, err)
	safe, err := pkcs12AuthenticatedSafe(pfx.AuthSafe)
	require.NoError(t, err)
	var contents []contentInfo
	_, err = asn1.Unmarshal(safe, &contents)
	require.NoError(t, err)
	require.Len(t, contents, 1)
	plain, err := pkcs12AuthenticatedSafe(contents[0])
	require.NoError(t, err)
	var bags []safeBag
	_, err = asn1.Unmarshal(plain, &bags)
	require.NoError(t, err)
	return pfx, bags
}

func TestPKCS12Export(t *testing.T) {
	first, second := p12Key(t), p12Key(t)
	firstCert := testiit.Certificate(t, first, false).Raw
	secondCert := testiit.Certificate(t, second, false).Raw
	extraCert := testiit.Certificate(t, p12Key(t), true).Raw
	raw1, err := MarshalRawKey(first)
	require.NoError(t, err)
	raw2, err := MarshalRawKey(second)
	require.NoError(t, err)
	certs := [][]byte{extraCert, secondCert, firstCert, firstCert}
	for _, password := range []string{"public-test-password", "ЇїЄєҐґ", strings.Repeat("ї", 16)} {
		data, err := MarshalPKCS12([][]byte{raw1, raw2}, certs, password)
		require.NoError(t, err)
		pairs, err := ParsePKCS12(data, password)
		require.NoError(t, err)
		require.Len(t, pairs, 2)
		require.Equal(t, first.D, pairs[0].PrivateKey.D)
		require.Equal(t, second.D, pairs[1].PrivateKey.D)
		require.Equal(t, firstCert, pairs[0].Cert)
		require.Equal(t, secondCert, pairs[1].Cert)
		require.Equal(t, [][]byte{extraCert}, pairs[0].CertChain)
		pfx, bags := exportedBags(t, data)
		require.Len(t, bags, 5)
		for _, bag := range bags[:2] {
			require.Equal(t, oidPKCS8ShroudedKeyBag, bag.BagID)
		}
		for _, raw := range [][]byte{raw1, raw2} {
			require.False(t, bytes.Contains(data, raw), "unencrypted PKCS8 must not be emitted")
		}
		// Reordered certificate bags carry the same localKeyId as their key.
		require.Equal(t, bags[0].BagAttrs.FullBytes, bags[4].BagAttrs.FullBytes)
		require.Equal(t, bags[1].BagAttrs.FullBytes, bags[3].BagAttrs.FullBytes)
		require.NotEmpty(t, bags[0].BagAttrs.FullBytes)
		require.NotEqual(t, bags[0].BagAttrs.FullBytes, bags[1].BagAttrs.FullBytes)
		require.Empty(t, bags[2].BagAttrs.FullBytes)
		pairs, err = ParsePKCS12(data, password+"wrong")
		require.ErrorIs(t, err, ErrPKCS12Integrity)
		require.Nil(t, pairs)
		// Alter authenticated bytes without updating the MAC, including both
		// the encrypted key and public certificate areas.
		for _, needle := range [][]byte{bags[0].BagValue.Bytes, firstCert} {
			altered := bytes.Clone(data)
			index := bytes.Index(altered, needle)
			require.GreaterOrEqual(t, index, 0)
			altered[index+len(needle)-1] ^= 1
			pairs, err = ParsePKCS12(altered, password)
			require.ErrorIs(t, err, ErrPKCS12Integrity)
			require.Nil(t, pairs)
		}
		pfx.MacData = asn1.RawValue{}
		pairs, err = ParsePKCS12(p12DER(t, pfx), password)
		require.ErrorIs(t, err, ErrPKCS12MissingMAC)
		require.Nil(t, pairs)
	}
	// Export never modifies caller-owned material.
	reencoded, err := MarshalRawKey(first)
	require.NoError(t, err)
	require.Equal(t, raw1, reencoded)
	require.Equal(t, firstCert, certs[2])
}

func TestPKCS12ExportFreshRandomness(t *testing.T) {
	key := p12Key(t)
	raw, err := MarshalRawKey(key)
	require.NoError(t, err)
	certificate := testiit.Certificate(t, key, false).Raw
	fields := func() [][]byte {
		data, err := MarshalPKCS12([][]byte{raw}, [][]byte{certificate}, "public")
		require.NoError(t, err)
		pfx, bags := exportedBags(t, data)
		var epki struct {
			Algorithm algorithmIdentifier
			Data      []byte
		}
		_, err = asn1.Unmarshal(bags[0].BagValue.Bytes, &epki)
		require.NoError(t, err)
		var params struct{ KDF, Cipher algorithmIdentifier }
		_, err = asn1.Unmarshal(epki.Algorithm.Parameters.FullBytes, &params)
		require.NoError(t, err)
		var kdf struct {
			Salt       []byte
			Iterations int
			PRF        algorithmIdentifier
		}
		_, err = asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kdf)
		require.NoError(t, err)
		var cipher struct{ IV []byte }
		_, err = asn1.Unmarshal(params.Cipher.Parameters.FullBytes, &cipher)
		require.NoError(t, err)
		var mac pkcs12MacData
		_, err = asn1.Unmarshal(pfx.MacData.FullBytes, &mac)
		require.NoError(t, err)
		require.Equal(t, 10000, kdf.Iterations)
		require.Equal(t, 10000, mac.Iterations)
		require.Equal(t, "2.16.840.1.101.3.4.2.1", mac.MAC.Algorithm.Algorithm.String())
		return [][]byte{kdf.Salt, cipher.IV, mac.Salt}
	}
	first, second := fields(), fields()
	for i := range first {
		require.Len(t, first[i], 32)
		require.Len(t, second[i], 32)
		require.NotEqual(t, first[i], second[i])
	}
}

func TestPKCS12ExportRejectsInvalidInput(t *testing.T) {
	key := p12Key(t)
	raw, err := MarshalRawKey(key)
	require.NoError(t, err)
	certificate := testiit.Certificate(t, key, false).Raw
	for _, password := range []string{"", strings.Repeat("p", 33), "a\x00b", "\xff", "\U0001f600"} {
		data, err := MarshalPKCS12([][]byte{raw}, [][]byte{certificate}, password)
		require.Error(t, err)
		require.Nil(t, data)
	}
	for _, tc := range []struct {
		name        string
		keys, certs [][]byte
	}{
		{"missing keys", nil, [][]byte{certificate}},
		{"missing certificates", [][]byte{raw}, nil},
		{"invalid key", [][]byte{{0x30, 0}}, [][]byte{certificate}},
		{"invalid certificate", [][]byte{raw}, [][]byte{{0x30, 0}}},
		{"unmatched key", [][]byte{raw}, [][]byte{testiit.Certificate(t, p12Key(t), false).Raw}},
		{"ambiguous certificate", [][]byte{raw}, [][]byte{certificate, testiit.Certificate(t, key, false).Raw}},
		{"duplicate key", [][]byte{raw, raw}, [][]byte{certificate}},
		{"key count", make([][]byte, 65), [][]byte{certificate}},
		{"certificate count", [][]byte{raw}, make([][]byte, 513)},
		{"size bound", [][]byte{bytes.Repeat([]byte{1}, (8<<20)+1)}, [][]byte{certificate}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := MarshalPKCS12(tc.keys, tc.certs, "public")
			require.Error(t, err)
			require.Nil(t, data)
		})
	}
	for _, available := range []int{0, 32, 64} {
		data, err := marshalPKCS12([][]byte{raw}, [][]byte{certificate}, "public", bytes.NewReader(make([]byte, available)))
		require.ErrorIs(t, err, io.EOF)
		require.Nil(t, data)
	}
}

// OpenSSL independently verifies the complete exported MAC and bag structure.
// It need not implement Kalyna because -noout does not decrypt private keys.
func TestPKCS12ExportOpenSSL(t *testing.T) {
	tool := os.Getenv("PKCS12_OPENSSL")
	if tool == "" {
		t.Skip("set PKCS12_OPENSSL for independent PFX verification")
	}
	key := p12Key(t)
	raw, err := MarshalRawKey(key)
	require.NoError(t, err)
	data, err := MarshalPKCS12([][]byte{raw}, [][]byte{testiit.Certificate(t, key, false).Raw}, "public-export-test")
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "disposable.pfx")
	require.NoError(t, os.WriteFile(path, data, 0600))
	output, err := exec.Command(tool, "pkcs12", "-info", "-noout", "-in", path, "-passin", "pass:public-export-test").CombinedOutput()
	require.NoError(t, err, "%s", output)
	require.Contains(t, string(output), "MAC: sha256, Iteration 10000")
	require.Contains(t, string(output), "Shrouded Keybag")
	require.Contains(t, string(output), "Certificate bag")
	output, err = exec.Command(tool, "pkcs12", "-info", "-noout", "-in", path, "-passin", "pass:wrong-password").CombinedOutput()
	require.Error(t, err)
	require.Contains(t, string(output), "Mac verify error")
}
