//go:build integration

package interop_test

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"math/big"
	"os"
	"slices"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/keystore"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/amaneshi/crypto-dstu/pkg/kupyna"
	"github.com/stretchr/testify/require"
)

// Test-only wire construction for unsupported modern ONB SPKI identifiers in the
// consumer library. No parser/signing allowlist is relaxed to run this probe.
func modernONBCertificate(t *testing.T, key *dstu4145.PrivateKey, bits int, modernCurve bool) []byte {
	t.Helper()
	type algorithmIdentifier struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	var outer struct {
		TBS       asn1.RawValue
		Algorithm algorithmIdentifier
		Signature asn1.BitString
	}
	rest, err := asn1.Unmarshal(testiit.NamedCertificate(t, key).Raw, &outer)
	require.NoError(t, err)
	require.Empty(t, rest)
	var fields []asn1.RawValue
	_, err = asn1.Unmarshal(outer.TBS.FullBytes, &fields)
	require.NoError(t, err)
	require.Len(t, fields, 8)
	profile := 1
	if bits == 512 {
		profile = 3
	}
	algorithm := asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 6, profile, 2}
	outer.Algorithm.Algorithm = algorithm
	encoded, err := asn1.Marshal(outer.Algorithm)
	require.NoError(t, err)
	fields[2] = asn1.RawValue{FullBytes: encoded}
	var public struct {
		Algorithm algorithmIdentifier
		Key       asn1.BitString
	}
	_, err = asn1.Unmarshal(fields[6].FullBytes, &public)
	require.NoError(t, err)
	var params struct {
		Curve asn1.ObjectIdentifier
		DKE   []byte `asn1:"optional"`
	}
	_, err = asn1.Unmarshal(public.Algorithm.Parameters.FullBytes, &params)
	require.NoError(t, err)
	if modernCurve {
		index := params.Curve[len(params.Curve)-1]
		params.Curve = append(slices.Clone(algorithm), 2, index)
	}
	params.DKE = nil
	encoded, err = asn1.Marshal(params)
	require.NoError(t, err)
	public.Algorithm = algorithmIdentifier{algorithm, asn1.RawValue{FullBytes: encoded}}
	encoded, err = asn1.Marshal(public)
	require.NoError(t, err)
	fields[6] = asn1.RawValue{FullBytes: encoded}
	// Key identifiers use Kupyna-256 for both supported Kupyna digest sizes.
	h := kupyna.New256()
	h.Write(public.Key.Bytes)
	keyID := h.Sum(nil)
	type extension struct {
		ID       asn1.ObjectIdentifier
		Critical bool `asn1:"optional"`
		Value    []byte
	}
	var extensions []extension
	_, err = asn1.Unmarshal(fields[7].Bytes, &extensions)
	require.NoError(t, err)
	for i := range extensions {
		switch {
		case extensions[i].ID.Equal(oid.OIDExtSubjectKeyID):
			extensions[i].Value, err = asn1.Marshal(keyID)
		case extensions[i].ID.Equal(oid.OIDExtAuthorityKeyID):
			extensions[i].Value, err = asn1.Marshal(struct {
				ID []byte `asn1:"tag:0"`
			}{keyID})
		}
		require.NoError(t, err)
	}
	encoded, err = asn1.Marshal(extensions)
	require.NoError(t, err)
	fields[7] = asn1.RawValue{Class: 2, Tag: 3, IsCompound: true, Bytes: encoded}
	tbs, err := asn1.Marshal(fields)
	require.NoError(t, err)
	if bits == 512 {
		h = kupyna.New512()
	} else {
		h.Reset()
	}
	h.Write(tbs)
	digest := h.Sum(nil)
	slices.Reverse(digest)
	signature, err := dstu4145.Sign(rand.Reader, key, digest)
	require.NoError(t, err)
	raw, err := dstu4145.MarshalSignatureRaw(signature, key.Curve)
	require.NoError(t, err)
	wrapped, err := asn1.Marshal(raw)
	require.NoError(t, err)
	outer.TBS = asn1.RawValue{FullBytes: tbs}
	outer.Signature = asn1.BitString{Bytes: wrapped, BitLength: len(wrapped) * 8}
	encoded, err = asn1.Marshal(outer)
	require.NoError(t, err)
	return encoded
}

func TestIITModernONBPublicKeyAlgorithmDiagnostic(t *testing.T) {
	if os.Getenv("IIT_ONB_DIAGNOSTIC") != "1" {
		t.Skip("enable modern ONB certificate diagnostic")
	}
	for _, name := range []string{"DSTU_ONB_173", "DSTU_ONB_179", "DSTU_ONB_191", "DSTU_ONB_233", "DSTU_ONB_431"} {
		curve := dstu4145.ParamsByName(name).Curve
		nBits := new(big.Int).SetBytes(curve.N).BitLen()
		d := new(big.Int).Lsh(big.NewInt(1), uint(nBits-2))
		d.Add(d, big.NewInt(0x12345))
		key := &dstu4145.PrivateKey{Curve: curve, D: d}
		raw, err := keystore.MarshalRawKey(key)
		require.NoError(t, err)
		container, err := keystore.MarshalKey6(raw, "disposable-onb", bytes.Repeat([]byte{0x53}, 32), 2, bytes.Repeat([]byte{0x49}, 8))
		require.NoError(t, err)
		for _, bits := range []int{256, 512} {
			for _, modernCurve := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%d/modern-curve=%t", name, bits, modernCurve), func(t *testing.T) {
					certificate := modernONBCertificate(t, key, bits, modernCurve)
					parsed := testiit.Invoke(t, testiit.Request{Operation: "cert-parse", Data: certificate})
					if !parsed.OK {
						require.Contains(t, parsed.Error, "EUParseCertificateEx: IIT error 50:")
					}
					t.Logf("parse=%t %s", parsed.OK, parsed.Error)
					signed := testiit.Invoke(t, testiit.Request{Operation: "sign", Digest: fmt.Sprintf("kupyna%d", bits), Detached: true, Data: []byte("modern ONB certificate diagnostic"), PrivateKey: container, Password: "disposable-onb", Certificates: [][]byte{certificate}})
					if !signed.OK {
						require.Regexp(t, `EUCtxReadPrivateKeyBinary: IIT error (33|50|51):`, signed.Error)
					}
					t.Logf("native sign=%t %s", signed.OK, signed.Error)
					if signed.OK {
						verified := testiit.Invoke(t, testiit.Request{Operation: "verify", Detached: true, Data: []byte("modern ONB certificate diagnostic"), Signature: signed.Data, Certificates: [][]byte{certificate}})
						require.True(t, verified.OK, verified.Error)
					}
				})
			}
		}
	}
}
