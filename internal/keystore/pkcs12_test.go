package keystore

import (
	"bytes"
	"crypto/hmac"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

func p12DER(t *testing.T, value any) []byte {
	t.Helper()
	der, err := asn1.Marshal(value)
	require.NoError(t, err)
	return der
}
func p12Explicit(der []byte) asn1.RawValue {
	return asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: der}
}
func p12Raw(t *testing.T, value any) asn1.RawValue {
	t.Helper()
	var raw asn1.RawValue
	_, err := asn1.Unmarshal(p12DER(t, value), &raw)
	require.NoError(t, err)
	return raw
}
func p12Sign(t *testing.T, safe []byte, password string) pfxASN {
	t.Helper()
	mac := pkcs12MacData{Salt: []byte("public test salt"), Iterations: 20}
	mac.MAC.Algorithm.Algorithm = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	newHash, err := pkcs12Hash(mac.MAC.Algorithm)
	require.NoError(t, err)
	encoded, err := pkcs12Password(password)
	require.NoError(t, err)
	key := pkcs12MACKey(newHash, encoded, mac.Salt, mac.Iterations)
	h := hmac.New(newHash, key)
	h.Write(safe)
	mac.MAC.Digest = h.Sum(nil)
	return pfxASN{Version: 3, AuthSafe: contentInfo{ContentType: oidDataContentType, Content: p12Explicit(p12DER(t, safe))}, MacData: p12Raw(t, mac)}
}
func p12Container(t *testing.T, bags []safeBag, password string) pfxASN {
	t.Helper()
	contents := contentInfo{ContentType: oidDataContentType, Content: p12Explicit(p12DER(t, p12DER(t, bags)))}
	return p12Sign(t, p12DER(t, []contentInfo{contents}), password)
}
func p12Key(t *testing.T) *dstu4145.PrivateKey {
	t.Helper()
	key, err := dstu4145.GenerateKey(dstu4145.ParamsByName("DSTU_PB_257").Curve)
	require.NoError(t, err)
	return key
}
func p12KeyBag(t *testing.T, key *dstu4145.PrivateKey, encrypted bool, password string) safeBag {
	t.Helper()
	raw, err := MarshalRawKey(key)
	require.NoError(t, err)
	oid := oidKeyBag
	if encrypted {
		raw, err = MarshalKey6(raw, password, bytes.Repeat([]byte{0x53}, 32), 20, bytes.Repeat([]byte{0x49}, 8))
		require.NoError(t, err)
		oid = oidPKCS8ShroudedKeyBag
	}
	return safeBag{BagID: oid, BagValue: p12Explicit(raw)}
}
func p12CertBag(t *testing.T, der []byte) safeBag {
	t.Helper()
	inner := struct {
		ID    asn1.ObjectIdentifier
		Value asn1.RawValue
	}{oidX509Certificate, p12Explicit(p12DER(t, der))}
	return safeBag{BagID: oidCertBag, BagValue: p12Explicit(p12DER(t, inner))}
}

func TestPKCS12OpenSSLMACVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/pkcs12-mac-openssl.json")
	require.NoError(t, err)
	var fixture struct {
		Producer string
		Vectors  []struct {
			Name, OID, Password, SaltHex, KeyHex, MessageHex, MacHex string
			Iterations                                               int
		}
	}
	require.NoError(t, json.Unmarshal(data, &fixture))
	require.NotEmpty(t, fixture.Producer)
	decode := func(value string) []byte {
		t.Helper()
		data, err := hex.DecodeString(value)
		require.NoError(t, err)
		return data
	}
	for _, v := range fixture.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			var oid asn1.ObjectIdentifier
			for _, part := range strings.Split(v.OID, ".") {
				n, err := strconv.Atoi(part)
				require.NoError(t, err)
				oid = append(oid, n)
			}
			algorithm := algorithmIdentifier{Algorithm: oid}
			newHash, err := pkcs12Hash(algorithm)
			require.NoError(t, err)
			encoded, err := pkcs12Password(v.Password)
			require.NoError(t, err)
			key := pkcs12MACKey(newHash, encoded, decode(v.SaltHex), v.Iterations)
			require.Equal(t, decode(v.KeyHex), key)
			mac := pkcs12MacData{Salt: decode(v.SaltHex), Iterations: v.Iterations}
			mac.MAC.Algorithm = algorithm
			mac.MAC.Digest = decode(v.MacHex)
			require.NoError(t, verifyPKCS12MAC(p12Raw(t, mac), decode(v.MessageHex), v.Password))
			require.ErrorIs(t, verifyPKCS12MAC(p12Raw(t, mac), decode(v.MessageHex), v.Password+"wrong"), ErrPKCS12Integrity)
		})
	}
}

func TestPKCS12IntegrityFailures(t *testing.T) {
	key := p12Key(t)
	makeContainer := func() pfxASN { return p12Container(t, []safeBag{p12KeyBag(t, key, false, "")}, "password") }
	for _, tc := range []struct {
		name     string
		mutate   func(*pfxASN)
		password string
		target   error
	}{
		{"wrong password", func(*pfxASN) {}, "incorrect", ErrPKCS12Integrity},
		{"missing MAC", func(p *pfxASN) { p.MacData = asn1.RawValue{} }, "password", ErrPKCS12MissingMAC},
		{"unsupported MAC", func(p *pfxASN) {
			var m pkcs12MacData
			_, err := asn1.Unmarshal(p.MacData.FullBytes, &m)
			require.NoError(t, err)
			m.MAC.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3, 4}
			p.MacData = p12Raw(t, m)
		}, "password", ErrPKCS12UnsupportedMAC},
		{"tampered safe", func(p *pfxASN) { p.AuthSafe.Content.Bytes[len(p.AuthSafe.Content.Bytes)-1] ^= 1 }, "password", ErrPKCS12Integrity},
		{"zero iterations", func(p *pfxASN) {
			var m pkcs12MacData
			_, err := asn1.Unmarshal(p.MacData.FullBytes, &m)
			require.NoError(t, err)
			m.Iterations = 0
			p.MacData = p12Raw(t, m)
		}, "password", nil},
		{"excessive iterations", func(p *pfxASN) {
			var m pkcs12MacData
			_, err := asn1.Unmarshal(p.MacData.FullBytes, &m)
			require.NoError(t, err)
			m.Iterations = 1_000_001
			p.MacData = p12Raw(t, m)
		}, "password", nil},
		{"malformed MAC", func(p *pfxASN) { p.MacData = p12Raw(t, []byte("invalid")) }, "password", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pfx := makeContainer()
			tc.mutate(&pfx)
			der := p12DER(t, pfx)
			pairs, err := ParsePKCS12(der, tc.password)
			require.Error(t, err)
			require.Nil(t, pairs)
			if tc.target != nil {
				require.ErrorIs(t, err, tc.target)
			}
			parsed, err := Parse(der, tc.password)
			require.Error(t, err)
			require.Nil(t, parsed)
			if tc.target != nil {
				require.ErrorIs(t, err, tc.target)
			}
		})
	}
}

func TestPKCS12PublicKeyAssociation(t *testing.T) {
	first, second, extra := p12Key(t), p12Key(t), p12Key(t)
	firstCert := testiit.Certificate(t, first, false).Raw
	secondCert := testiit.Certificate(t, second, false).Raw
	extraCert := testiit.Certificate(t, extra, true).Raw
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprint("encrypted=", encrypted), func(t *testing.T) {
			bags := []safeBag{p12CertBag(t, extraCert), p12KeyBag(t, first, encrypted, "password"), p12CertBag(t, secondCert), p12CertBag(t, firstCert), p12KeyBag(t, second, encrypted, "password"), p12CertBag(t, firstCert)}
			data := p12DER(t, p12Container(t, bags, "password"))
			pairs, err := ParsePKCS12(data, "password")
			require.NoError(t, err)
			require.Len(t, pairs, 2)
			require.Equal(t, firstCert, pairs[0].Cert)
			require.Equal(t, secondCert, pairs[1].Cert)
			for _, pair := range pairs {
				require.Equal(t, [][]byte{extraCert}, pair.CertChain)
			}
			parsed, err := Parse(data, "password")
			require.NoError(t, err)
			require.Len(t, parsed.Keys, 2)
			require.Len(t, parsed.Certs, 3)
		})
	}
	t.Run("ambiguous certificate", func(t *testing.T) {
		another := testiit.Certificate(t, first, false).Raw
		data := p12DER(t, p12Container(t, []safeBag{p12KeyBag(t, first, false, ""), p12CertBag(t, firstCert), p12CertBag(t, another)}, "password"))
		pairs, err := ParsePKCS12(data, "password")
		require.ErrorContains(t, err, "ambiguous")
		require.Nil(t, pairs)
	})
	t.Run("duplicate key", func(t *testing.T) {
		bag := p12KeyBag(t, first, false, "")
		pairs, err := ParsePKCS12(p12DER(t, p12Container(t, []safeBag{bag, bag}, "password")), "password")
		require.ErrorContains(t, err, "duplicate private key")
		require.Nil(t, pairs)
	})
	t.Run("unmatched certificate", func(t *testing.T) {
		pairs, err := ParsePKCS12(p12DER(t, p12Container(t, []safeBag{p12KeyBag(t, first, false, ""), p12CertBag(t, secondCert)}, "password")), "password")
		require.NoError(t, err)
		require.Nil(t, pairs[0].Cert)
		require.Equal(t, [][]byte{secondCert}, pairs[0].CertChain)
	})
}

func TestPKCS12AuthenticatedMalformedBags(t *testing.T) {
	key := p12Key(t)
	valid := p12KeyBag(t, key, false, "")
	for _, tc := range []struct {
		name string
		bags []safeBag
	}{
		{"malformed certificate", []safeBag{valid, p12CertBag(t, []byte{0x30, 0})}},
		{"unsupported bag", []safeBag{valid, {BagID: asn1.ObjectIdentifier{1, 2, 3}, BagValue: p12Explicit([]byte{5, 0})}}},
		{"wrong key wrapper", []safeBag{{BagID: oidKeyBag, BagValue: asn1.RawValue{Tag: 4, Bytes: []byte{1, 2, 3}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pairs, err := ParsePKCS12(p12DER(t, p12Container(t, tc.bags, "password")), "password")
			require.Error(t, err)
			require.Nil(t, pairs)
		})
	}
	validPFX := p12DER(t, p12Container(t, []safeBag{valid}, "password"))
	t.Run("trailing bytes", func(t *testing.T) {
		pairs, err := ParsePKCS12(append(validPFX, 0), "password")
		require.Error(t, err)
		require.Nil(t, pairs)
	})
	t.Run("trailing authenticated contents", func(t *testing.T) {
		pfx := p12Sign(t, []byte{0x30, 0, 0x05, 0}, "password")
		pairs, err := ParsePKCS12(p12DER(t, pfx), "password")
		require.Error(t, err)
		require.Nil(t, pairs)
	})
	t.Run("short unrelated OID", func(t *testing.T) {
		pfx := pfxASN{Version: 3, AuthSafe: contentInfo{ContentType: asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6}}}
		require.False(t, looksLikePKCS12(p12DER(t, pfx)))
	})
}

func TestPKCS12PasswordPolicy(t *testing.T) {
	for _, password := range []string{"\xff", "supplementary\U0001f600", strings.Repeat("p", 4097)} {
		_, err := pkcs12Password(password)
		require.Error(t, err)
	}
	t.Run("legacy empty encoding", func(t *testing.T) {
		mac := pkcs12MacData{Salt: []byte("public salt"), Iterations: 20}
		mac.MAC.Algorithm.Algorithm = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
		newHash, err := pkcs12Hash(mac.MAC.Algorithm)
		require.NoError(t, err)
		key := pkcs12MACKey(newHash, nil, mac.Salt, mac.Iterations)
		h := hmac.New(newHash, key)
		h.Write([]byte("public content"))
		mac.MAC.Digest = h.Sum(nil)
		require.NoError(t, verifyPKCS12MAC(p12Raw(t, mac), []byte("public content"), ""))
		require.ErrorIs(t, verifyPKCS12MAC(p12Raw(t, mac), []byte("public content"), "nonempty"), ErrPKCS12Integrity)
	})
}
