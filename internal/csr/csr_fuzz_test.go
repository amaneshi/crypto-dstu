package csr

import (
	"bytes"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

func FuzzParseAndVerify(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x30, 0})
	f.Add([]byte{0x30, 0x80, 0, 0})
	f.Add(legacyCSRSeed(f))
	for _, profile := range []struct {
		curve     string
		algorithm asn1.ObjectIdentifier
	}{
		{"DSTU_PB_257", nil},
		{"DSTU_ONB_173", nil},
		{"DSTU_PB_257", oid.DSTU4145WithKupyna256},
		{"DSTU_PB_431", oid.DSTU4145WithKupyna512},
		{"DSTU_ONB_173", oid.DSTU4145ONBWithKupyna256},
		{"DSTU_ONB_431", oid.DSTU4145ONBWithKupyna512},
	} {
		// Deliberately public fixture scalar, never an operational credential.
		key := &dstu4145.PrivateKey{Curve: dstu4145.ParamsByName(profile.curve).Curve, D: big.NewInt(2)}
		seed, err := Create(&Request{
			Subject:               []AttributeTypeAndValue{{Type: oid.OIDCommonName, Value: "CSR fuzz seed"}},
			SignatureAlgorithmOID: profile.algorithm,
		}, key)
		require.NoError(f, err)
		parsed, err := Parse(seed)
		require.NoError(f, err)
		require.NoError(f, parsed.Verify())
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		original := bytes.Clone(data)
		parsed, err := Parse(data)
		require.Equal(t, original, data, "parsing changed the caller's input")
		if err != nil {
			require.Nil(t, parsed, "failed parsing released a request")
			return
		}
		require.NotNil(t, parsed)
		require.NotNil(t, parsed.PublicKey)
		require.Equal(t, data, parsed.Raw)
		withJunk, err := Parse(append(bytes.Clone(data), 0))
		require.Error(t, err)
		require.Nil(t, withJunk)
		// Parsing does not authenticate. Exercise verification even for requests
		// whose DER is valid but whose signature has been mutated by the fuzzer.
		if parsed.Verify() == nil {
			changed := *parsed
			changed.CRIRaw = bytes.Clone(parsed.CRIRaw)
			changed.CRIRaw[len(changed.CRIRaw)-1] ^= 1
			require.Error(t, changed.Verify(), "modified signed information was accepted")
			changed = *parsed
			changed.SignatureBytes = bytes.Clone(parsed.SignatureBytes)
			changed.SignatureBytes[len(changed.SignatureBytes)-1] ^= 1
			require.Error(t, changed.Verify(), "modified signature was accepted")
		}
		require.Equal(t, original, data, "verification changed the caller's input")
	})
}
