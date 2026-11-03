package keystore

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

func TestPKCS12PBMAC1Unicode(t *testing.T) {
	key := &dstu4145.PrivateKey{Curve: dstu4145.ParamsByName("DSTU_PB_257").Curve, D: big.NewInt(2)}
	raw, err := MarshalRawKey(key)
	require.NoError(t, err)
	certificate := testiit.Certificate(t, key, false)
	for _, tc := range []struct{ name, password, wrong string }{
		{"CJK", "密碼テスト", "密碼テス卜"},
		{"Arabic", "كلمةالسر", "كلمةالسر1"},
		{"Devanagari", "पासवर्ड", "पासवर्ड1"},
		{"emoji", "🔑😀пароль", "🔑😁пароль"},
		{"composed", "café", "cafe\u0301"},
		{"decomposed", "cafe\u0301", "café"},
		{"supplementary-letter", "𐐀𐐨", "𐐁𐐨"},
		{"32-UTF8-bytes", strings.Repeat("😀", 8), strings.Repeat("😀", 7)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := MarshalPKCS12WithOptions([][]byte{raw}, [][]byte{certificate.Raw}, tc.password, PKCS12ExportOptions{Integrity: PKCS12IntegrityPBMAC1SHA256})
			require.NoError(t, err)
			pairs, err := ParsePKCS12(data, tc.password)
			require.NoError(t, err)
			require.Len(t, pairs, 1)
			require.Equal(t, key.D, pairs[0].PrivateKey.D)
			require.Equal(t, certificate.Raw, pairs[0].Cert)
			pairs, err = ParsePKCS12(data, tc.wrong)
			require.ErrorIs(t, err, ErrPKCS12Integrity)
			require.Nil(t, pairs)
			var pfx pfxASN
			_, err = asn1.Unmarshal(data, &pfx)
			require.NoError(t, err)
			var mac pkcs12MacData
			_, err = asn1.Unmarshal(pfx.MacData.FullBytes, &mac)
			require.NoError(t, err)
			require.Equal(t, oidPBMAC1, mac.MAC.Algorithm.Algorithm)
			safe, err := pkcs12AuthenticatedSafe(pfx.AuthSafe)
			require.NoError(t, err)
			safe = bytes.Clone(safe)
			safe[len(safe)-1] ^= 1
			pfx.AuthSafe.Content = p12Explicit(p12DER(t, safe))
			pairs, err = ParsePKCS12(p12DER(t, pfx), tc.password)
			require.ErrorIs(t, err, ErrPKCS12Integrity)
			require.Nil(t, pairs)
		})
	}
	for _, tc := range []struct{ name, password string }{
		{"empty", ""}, {"invalid UTF8", string([]byte{0xff})}, {"NUL", "a\x00b"}, {"over32", strings.Repeat("😀", 9)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := MarshalPKCS12WithOptions([][]byte{raw}, [][]byte{certificate.Raw}, tc.password, PKCS12ExportOptions{Integrity: PKCS12IntegrityPBMAC1SHA256})
			require.Error(t, err)
			require.Nil(t, data)
		})
	}
	data, err := MarshalPKCS12([][]byte{raw}, [][]byte{certificate.Raw}, "😀")
	require.Error(t, err)
	require.Nil(t, data)
	data, err = MarshalPKCS12WithOptions([][]byte{raw}, [][]byte{certificate.Raw}, "public", PKCS12ExportOptions{Integrity: "unknown"})
	require.Error(t, err)
	require.Nil(t, data)
}

func TestPBMAC1RejectsParameters(t *testing.T) {
	safe := []byte("exact public AuthenticatedSafe bytes")
	original, err := makePBMAC1(safe, "密碼😀", []byte("public test salt"), 2)
	require.NoError(t, err)
	for _, tc := range []struct {
		name   string
		mutate func(*pkcs12MacData, *pbmac1Params, *pbkdf2Params)
	}{
		{"missing key length", func(_ *pkcs12MacData, _ *pbmac1Params, k *pbkdf2Params) { k.KeyLength = 0 }},
		{"short key", func(_ *pkcs12MacData, _ *pbmac1Params, k *pbkdf2Params) { k.KeyLength = 19 }},
		{"large key", func(_ *pkcs12MacData, _ *pbmac1Params, k *pbkdf2Params) { k.KeyLength = 65 }},
		{"zero iterations", func(_ *pkcs12MacData, _ *pbmac1Params, k *pbkdf2Params) { k.Iterations = 0 }},
		{"excessive iterations", func(_ *pkcs12MacData, _ *pbmac1Params, k *pbkdf2Params) { k.Iterations = 1_000_001 }},
		{"empty salt", func(_ *pkcs12MacData, _ *pbmac1Params, k *pbkdf2Params) { k.Salt = nil }},
		{"excessive salt", func(_ *pkcs12MacData, _ *pbmac1Params, k *pbkdf2Params) { k.Salt = make([]byte, 1025) }},
		{"SHA1 default", func(_ *pkcs12MacData, _ *pbmac1Params, k *pbkdf2Params) { k.PRF = algorithmIdentifier{} }},
		{"unknown PRF", func(_ *pkcs12MacData, _ *pbmac1Params, k *pbkdf2Params) {
			k.PRF.Algorithm = asn1.ObjectIdentifier{1, 2, 3}
		}},
		{"invalid PRF params", func(_ *pkcs12MacData, _ *pbmac1Params, k *pbkdf2Params) {
			k.PRF.Parameters = asn1.RawValue{Tag: asn1.TagInteger, Bytes: []byte{1}}
		}},
		{"unknown MAC", func(_ *pkcs12MacData, p *pbmac1Params, _ *pbkdf2Params) {
			p.MAC.Algorithm = asn1.ObjectIdentifier{1, 2, 3}
		}},
		{"invalid MAC params", func(_ *pkcs12MacData, p *pbmac1Params, _ *pbkdf2Params) {
			p.MAC.Parameters = asn1.RawValue{Tag: asn1.TagInteger, Bytes: []byte{1}}
		}},
		{"unknown KDF", func(_ *pkcs12MacData, p *pbmac1Params, _ *pbkdf2Params) {
			p.KDF.Algorithm = asn1.ObjectIdentifier{1, 2, 3}
		}},
		{"truncated digest", func(m *pkcs12MacData, _ *pbmac1Params, _ *pbkdf2Params) { m.MAC.Digest = m.MAC.Digest[:31] }},
		{"wrong digest", func(m *pkcs12MacData, _ *pbmac1Params, _ *pbkdf2Params) { m.MAC.Digest = bytes.Repeat([]byte{0}, 32) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := original
			var p pbmac1Params
			_, err := asn1.Unmarshal(m.MAC.Algorithm.Parameters.FullBytes, &p)
			require.NoError(t, err)
			var k pbkdf2Params
			_, err = asn1.Unmarshal(p.KDF.Parameters.FullBytes, &k)
			require.NoError(t, err)
			tc.mutate(&m, &p, &k)
			p.KDF.Parameters = asn1.RawValue{FullBytes: p12DER(t, k)}
			m.MAC.Algorithm.Parameters = asn1.RawValue{FullBytes: p12DER(t, p)}
			require.Error(t, verifyPKCS12MAC(p12Raw(t, m), safe, "密碼😀"))
		})
	}
	// The outer legacy fields are deliberately ignored, as RFC 9879 requires.
	ignored := original
	ignored.Salt = nil
	ignored.Iterations = -7
	require.NoError(t, verifyPKCS12MAC(p12Raw(t, ignored), safe, "密碼😀"))
	for _, bad := range [][]byte{nil, {5, 0}, append(bytes.Clone(original.MAC.Algorithm.Parameters.FullBytes), 0)} {
		m := original
		m.MAC.Algorithm.Parameters = asn1.RawValue{FullBytes: bad}
		require.Error(t, verifyPKCS12MAC(p12Raw(t, m), safe, "密碼😀"))
	}
	for _, password := range []string{string([]byte{0xff}), strings.Repeat("a", 4097)} {
		require.Error(t, verifyPKCS12MAC(p12Raw(t, original), safe, password))
	}
}

type pbmac1Fixture struct {
	Name, Password string
	PFX            []byte
}
type pbmac1Fixtures struct {
	Producer, Validation string
	Samples              []pbmac1Fixture
}

// OpenSSL verifies complete exported national-key containers and independently
// produces PBMAC1 MAC parameters/digests for certificate-only fixtures.
func TestPBMAC1OpenSSL(t *testing.T) {
	tool := os.Getenv("PKCS12_OPENSSL")
	if tool == "" {
		t.Skip("set PKCS12_OPENSSL for independent PBMAC1 checks")
	}
	version, err := exec.Command(tool, "version").CombinedOutput()
	require.NoError(t, err)
	key := &dstu4145.PrivateKey{Curve: dstu4145.ParamsByName("DSTU_PB_257").Curve, D: big.NewInt(2)}
	raw, err := MarshalRawKey(key)
	require.NoError(t, err)
	certificate := testiit.Certificate(t, key, false)
	var samples []pbmac1Fixture
	for _, profile := range []struct{ name, password, mac, prf string }{
		{"CJK-SHA256", "密碼テスト", "SHA256", "SHA256"},
		{"Arabic-mixed-SHA512", "كلمةالسر", "SHA256", "SHA512"},
		{"emoji-SHA512", "🔑😀пароль", "SHA512", "SHA512"},
		{"composed", "café", "SHA256", "SHA256"},
		{"decomposed", "cafe\u0301", "SHA256", "SHA256"},
		{"32-byte", "😀😀😀😀😀😀😀😀", "SHA256", "SHA256"},
		{"Devanagari-SHA224", "पासवर्ड", "SHA224", "SHA224"},
		{"Greek-SHA384", "Κωδικός", "SHA384", "SHA384"},
	} {
		t.Run(profile.name, func(t *testing.T) {
			dir := t.TempDir()
			passwordPath := filepath.Join(dir, "public-password.txt")
			require.NoError(t, os.WriteFile(passwordPath, []byte(profile.password+"\n"), 0600))
			data, err := MarshalPKCS12WithOptions([][]byte{raw}, [][]byte{certificate.Raw}, profile.password, PKCS12ExportOptions{Integrity: PKCS12IntegrityPBMAC1SHA256})
			require.NoError(t, err)
			path := filepath.Join(dir, "public-go.pfx")
			require.NoError(t, os.WriteFile(path, data, 0600))
			output, err := exec.Command(tool, "pkcs12", "-info", "-noout", "-in", path, "-passin", "file:"+passwordPath).CombinedOutput()
			require.NoError(t, err, "%s", output)
			require.Contains(t, string(output), "PBMAC1")
			require.Contains(t, string(output), "Shrouded Keybag")
			output, err = exec.Command(tool, "pkcs12", "-noout", "-in", path, "-passin", "pass:wrong-password").CombinedOutput()
			require.Error(t, err, "%s", output)
			samples = append(samples, pbmac1Fixture{"Go-" + profile.name, profile.password, data})
			certPath := filepath.Join(dir, "public-cert.pem")
			require.NoError(t, os.WriteFile(certPath, EncodePEM(certificate.Raw, "CERTIFICATE"), 0600))
			path = filepath.Join(dir, "public-openssl.pfx")
			output, err = exec.Command(tool, "pkcs12", "-export", "-nokeys", "-certpbe", "NONE", "-in", certPath, "-out", path, "-passout", "file:"+passwordPath, "-pbmac1_pbkdf2", "-macalg", profile.mac, "-pbmac1_pbkdf2_md", profile.prf, "-iter", "20").CombinedOutput()
			require.NoError(t, err, "%s", output)
			data, err = os.ReadFile(path)
			require.NoError(t, err)
			var pfx pfxASN
			_, err = asn1.Unmarshal(data, &pfx)
			require.NoError(t, err)
			safe, err := pkcs12AuthenticatedSafe(pfx.AuthSafe)
			require.NoError(t, err)
			require.NoError(t, verifyPKCS12MAC(pfx.MacData, safe, profile.password))
			require.ErrorIs(t, verifyPKCS12MAC(pfx.MacData, safe, profile.password+"wrong"), ErrPKCS12Integrity)
			samples = append(samples, pbmac1Fixture{"OpenSSL-" + profile.name, profile.password, data})
		})
	}
	if path := os.Getenv("PKCS12_CAPTURE_PBMAC1"); path != "" && !t.Failed() {
		require.True(t, filepath.IsAbs(path))
		require.Len(t, samples, 16)
		encoded, err := json.MarshalIndent(pbmac1Fixtures{strings.TrimSpace(string(version)), "Public scalar d=2. Go national-key PFX verified by OpenSSL (-noout skips Kalyna decryption); OpenSSL certificate-only PFX independently supplies SHA-2 PRF and MAC checks. No private operational keys.", samples}, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, append(encoded, '\n'), 0600))
	}
}

func TestPBMAC1RetainedFixtures(t *testing.T) {
	data, err := os.ReadFile("testdata/pkcs12-pbmac1-openssl.json")
	if os.IsNotExist(err) {
		t.Fatal("missing independent PBMAC1 fixtures")
	}
	require.NoError(t, err)
	var fixture pbmac1Fixtures
	require.NoError(t, json.Unmarshal(data, &fixture))
	require.Contains(t, fixture.Producer, "OpenSSL 3.5.9")
	require.Len(t, fixture.Samples, 16)
	for _, sample := range fixture.Samples {
		t.Run(sample.Name, func(t *testing.T) {
			var pfx pfxASN
			_, err := asn1.Unmarshal(sample.PFX, &pfx)
			require.NoError(t, err)
			safe, err := pkcs12AuthenticatedSafe(pfx.AuthSafe)
			require.NoError(t, err)
			require.NoError(t, verifyPKCS12MAC(pfx.MacData, safe, sample.Password))
			pairs, err := ParsePKCS12(sample.PFX, sample.Password)
			if strings.HasPrefix(sample.Name, "Go-") {
				require.NoError(t, err)
				require.Len(t, pairs, 1)
				require.Equal(t, int64(2), pairs[0].PrivateKey.D.Int64())
				t.Run("UAPKIPrivacy", func(t *testing.T) { checkUnicodePrivacy(t, sample, safe, pairs[0].PrivateKey) })
			} else {
				require.ErrorContains(t, err, "no private keys")
				require.Nil(t, pairs)
			}
			pairs, err = ParsePKCS12(sample.PFX, sample.Password+"wrong")
			require.ErrorIs(t, err, ErrPKCS12Integrity)
			require.Nil(t, pairs)
			// Force a valid outer PFX with changed authenticated content through the MAC gate.
			safe = bytes.Clone(safe)
			safe[len(safe)-1] ^= 1
			pfx.AuthSafe.Content = p12Explicit(p12DER(t, safe))
			pairs, err = ParsePKCS12(p12DER(t, pfx), sample.Password)
			require.ErrorIs(t, err, ErrPKCS12Integrity)
			require.Nil(t, pairs)
		})
	}
}

func checkUnicodePrivacy(t *testing.T, sample pbmac1Fixture, safe []byte, key *dstu4145.PrivateKey) {
	t.Helper()
	tool := os.Getenv("UNICODE_KEY6_UAPKI_WSL")
	if tool == "" {
		t.Skip("set UNICODE_KEY6_UAPKI_WSL for independent national-key privacy checks")
	}
	var contents []contentInfo
	_, err := asn1.Unmarshal(safe, &contents)
	require.NoError(t, err)
	require.Len(t, contents, 1)
	var inner []byte
	_, err = asn1.Unmarshal(contents[0].Content.Bytes, &inner)
	require.NoError(t, err)
	var bags []safeBag
	_, err = asn1.Unmarshal(inner, &bags)
	require.NoError(t, err)
	require.Equal(t, oidPKCS8ShroudedKeyBag, bags[0].BagID)
	var encrypted encryptedPrivateKeyInfo
	_, err = asn1.Unmarshal(bags[0].BagValue.Bytes, &encrypted)
	require.NoError(t, err)
	parameters, kdf, err := parsePBES2Parameters(encrypted.Algorithm)
	require.NoError(t, err)
	require.Equal(t, oidKupynaKMAC256, kdf.PRF.Algorithm)
	require.Equal(t, oidKalyna256CBC, parameters.EncScheme.Algorithm)
	var iv struct{ IV []byte }
	_, err = asn1.Unmarshal(parameters.EncScheme.Parameters.FullBytes, &iv)
	require.NoError(t, err)
	raw, err := MarshalRawKey(key)
	require.NoError(t, err)
	frame := []byte("UKP1")
	field := func(data []byte) {
		frame = binary.LittleEndian.AppendUint32(frame, uint32(len(data)))
		frame = append(frame, data...)
	}
	field([]byte(sample.Password))
	field(kdf.Salt)
	frame = binary.LittleEndian.AppendUint32(frame, uint32(kdf.Iterations))
	field(iv.IV)
	field(encrypted.EncryptedData)
	field(raw)
	path := filepath.Join(t.TempDir(), "public-privacy.bin")
	wslPath := "/mnt/" + strings.ToLower(filepath.VolumeName(path)[:1]) + strings.ReplaceAll(path[len(filepath.VolumeName(path)):], "\\", "/")
	require.NoError(t, os.WriteFile(path, frame, 0600))
	output, err := exec.Command("wsl.exe", "-d", "Ubuntu", "--exec", tool, wslPath).CombinedOutput()
	require.NoError(t, err, "%s", output)
	require.Contains(t, string(output), "UAPKI Unicode privacy verified")
	// This public frame contains the password as bytes, never an operational key.
	frame[8] ^= 1
	require.NoError(t, os.WriteFile(path, frame, 0600))
	output, err = exec.Command("wsl.exe", "-d", "Ubuntu", "--exec", tool, wslPath).CombinedOutput()
	require.Error(t, err, "%s", output)
}
