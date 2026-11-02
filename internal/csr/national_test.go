package csr

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

func csrDER(t *testing.T, value any) []byte {
	t.Helper()
	data, err := asn1.Marshal(value)
	require.NoError(t, err)
	return data
}

func TestNationalCSRProfiles(t *testing.T) {
	for _, params := range dstu4145.AllParams() {
		t.Run(params.Name, func(t *testing.T) {
			key := &dstu4145.PrivateKey{Curve: params.Curve, D: big.NewInt(2)} // public fixture scalar
			data, err := Create(&Request{Subject: []AttributeTypeAndValue{{oid.OIDCommonName, "CSR interoperability"}}}, key)
			require.NoError(t, err)
			parsed, err := Parse(data)
			require.NoError(t, err)
			require.NoError(t, parsed.Verify())
			require.True(t, parsed.national)
			require.True(t, key.Public().Q.Equal(parsed.PublicKey.Q))
			var outer certificationRequest
			_, err = asn1.Unmarshal(data, &outer)
			require.NoError(t, err)
			var info certificationRequestInfo
			_, err = asn1.Unmarshal(outer.CertificationRequestInfo.FullBytes, &info)
			require.NoError(t, err)
			require.Equal(t, []byte{0xa0, 0}, info.Attributes.FullBytes)
			var compressed, signature []byte
			_, err = asn1.Unmarshal(info.PublicKey.PublicKey.Bytes, &compressed)
			require.NoError(t, err)
			require.Len(t, compressed, (params.Curve.M+7)/8)
			_, err = asn1.Unmarshal(outer.Signature.Bytes, &signature)
			require.NoError(t, err)
			require.Len(t, signature, 2*((new(big.Int).SetBytes(params.Curve.N).BitLen()+7)/8))
			for _, mutate := range []func(*certificationRequest, *certificationRequestInfo){
				func(o *certificationRequest, i *certificationRequestInfo) { i.Version = 1 },
				func(o *certificationRequest, i *certificationRequestInfo) { i.Attributes = asn1.RawValue{} },
				func(o *certificationRequest, i *certificationRequestInfo) {
					o.SignatureAlgorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3}
				},
				func(o *certificationRequest, i *certificationRequestInfo) { i.PublicKey.PublicKey.BitLength-- },
				func(o *certificationRequest, i *certificationRequestInfo) {
					i.PublicKey.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3}
				},
				func(o *certificationRequest, i *certificationRequestInfo) {
					i.Subject = asn1.RawValue{FullBytes: csrDER(t, 1)}
				},
				func(o *certificationRequest, i *certificationRequestInfo) {
					i.Attributes = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: []byte{5, 0}}
				},
				func(o *certificationRequest, i *certificationRequestInfo) {
					var p struct {
						Curve asn1.RawValue
						DKE   []byte `asn1:"optional"`
					}
					_, e := asn1.Unmarshal(i.PublicKey.Algorithm.Parameters.FullBytes, &p)
					require.NoError(t, e)
					p.DKE[0] ^= 1
					i.PublicKey.Algorithm.Parameters = asn1.RawValue{FullBytes: csrDER(t, p)}
				},
			} {
				var changed certificationRequest
				_, err = asn1.Unmarshal(data, &changed)
				require.NoError(t, err)
				var changedInfo certificationRequestInfo
				_, err = asn1.Unmarshal(changed.CertificationRequestInfo.FullBytes, &changedInfo)
				require.NoError(t, err)
				mutate(&changed, &changedInfo)
				changed.CertificationRequestInfo = asn1.RawValue{FullBytes: csrDER(t, changedInfo)}
				_, err = Parse(csrDER(t, changed))
				require.Error(t, err)
			}
			altered := bytes.Replace(data, []byte("CSR interoperability"), []byte("BAD interoperability"), 1)
			bad, err := Parse(altered)
			require.NoError(t, err)
			require.Error(t, bad.Verify())
			_, err = Parse(append(data, 0))
			require.Error(t, err)
		})
	}
}

func TestNationalCSRModernPBProfiles(t *testing.T) {
	for _, algorithm := range []asn1.ObjectIdentifier{oid.DSTU4145WithKupyna256, oid.DSTU4145WithKupyna512} {
		key := &dstu4145.PrivateKey{Curve: dstu4145.ParamsByName("DSTU_PB_431").Curve, D: big.NewInt(2)}
		data, err := Create(&Request{SignatureAlgorithmOID: algorithm}, key)
		require.NoError(t, err)
		parsed, err := Parse(data)
		require.NoError(t, err)
		require.NoError(t, parsed.Verify())
		key.Curve = dstu4145.ParamsByName("DSTU_ONB_431").Curve
		data, err = Create(&Request{SignatureAlgorithmOID: algorithm}, key)
		require.Error(t, err)
		require.Nil(t, data)
	}
}

func TestLegacyCSRImport(t *testing.T) {
	params := dstu4145.ParamsByName("DSTU_PB_257")
	key := &dstu4145.PrivateKey{Curve: params.Curve, D: big.NewInt(2)}
	public := key.Public()
	size := (key.Curve.M + 7) / 8
	x := new(big.Int).SetBytes(public.Q.X.Bytes()).FillBytes(make([]byte, size))
	y := new(big.Int).SetBytes(public.Q.Y.Bytes()).FillBytes(make([]byte, size))
	spki := subjectPublicKeyInfo{Algorithm: algorithmIdentifier{Algorithm: params.HashOID, Parameters: asn1.RawValue{FullBytes: csrDER(t, params.OID)}}, PublicKey: asn1.BitString{Bytes: append(x, y...), BitLength: 16 * size}}
	info := certificationRequestInfo{Subject: asn1.RawValue{FullBytes: []byte{0x30, 0}}, PublicKey: spki}
	raw := csrDER(t, info)
	digest, err := hashData(raw, params.HashOID)
	require.NoError(t, err)
	sig, err := dstu4145.Sign(rand.Reader, key, digest)
	require.NoError(t, err)
	signature, err := dstu4145.MarshalSignature(sig)
	require.NoError(t, err)
	data := csrDER(t, certificationRequest{CertificationRequestInfo: asn1.RawValue{FullBytes: raw}, SignatureAlgorithm: algorithmIdentifier{Algorithm: params.HashOID}, Signature: asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)}})
	parsed, err := Parse(data)
	require.NoError(t, err)
	require.False(t, parsed.national)
	require.NoError(t, parsed.Verify())
}

func TestCSRIndependentVerification(t *testing.T) {
	tool := os.Getenv("CSR_CRYPTONITE_WSL")
	openssl := os.Getenv("PKCS12_OPENSSL")
	if tool == "" || openssl == "" {
		t.Skip("set CSR_CRYPTONITE_WSL and PKCS12_OPENSSL for independent CSR checks")
	}
	for _, params := range dstu4145.AllParams() {
		t.Run(params.Name, func(t *testing.T) {
			key := &dstu4145.PrivateKey{Curve: params.Curve, D: big.NewInt(2)}
			algorithms := []asn1.ObjectIdentifier{params.HashOID}
			if params.Name == "DSTU_PB_257" {
				algorithms = append(algorithms, oid.DSTU4145WithKupyna256)
			}
			for _, algorithm := range algorithms {
				t.Logf("independent CSR signature algorithm %s", algorithm)
				data, err := Create(&Request{SignatureAlgorithmOID: algorithm, Subject: []AttributeTypeAndValue{{oid.OIDCommonName, "CSR interoperability"}}}, key)
				require.NoError(t, err)
				local, err := Parse(data)
				require.NoError(t, err)
				require.NoError(t, local.Verify())
				path := filepath.Join(t.TempDir(), "public-request.der")
				require.NoError(t, os.WriteFile(path, data, 0600))
				output, err := exec.Command(openssl, "req", "-inform", "DER", "-in", path, "-noout", "-subject").CombinedOutput()
				require.NoError(t, err, "%s", output)
				require.Contains(t, string(output), "CSR interoperability")
				wslPath := "/mnt/" + strings.ToLower(filepath.VolumeName(path)[:1]) + strings.ReplaceAll(path[len(filepath.VolumeName(path)):], "\\", "/")
				output, err = exec.Command("wsl.exe", "-d", "Ubuntu", "--exec", tool, wslPath).CombinedOutput()
				require.NoError(t, err, "%s", output)
				require.Contains(t, string(output), "Cryptonite CSR signature verified")
				altered := bytes.Replace(data, []byte("CSR interoperability"), []byte("BAD interoperability"), 1)
				require.NoError(t, os.WriteFile(path, altered, 0600))
				_, err = exec.Command("wsl.exe", "-d", "Ubuntu", "--exec", tool, wslPath).CombinedOutput()
				require.Error(t, err)
			}
		})
	}
}
