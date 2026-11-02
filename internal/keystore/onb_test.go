package keystore

import (
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

func TestRawKeysRejectUnsupportedONB(t *testing.T) {
	for index, name := range []string{"ONB173", "ONB179", "ONB191", "ONB233", "ONB431"} {
		t.Run(name, func(t *testing.T) {
			// Use an intentionally public scalar, then replace only the named
			// curve. Neither bit length nor a known signature algorithm may
			// cause an unsupported ONB key to fall back to a PB curve.
			key := &dstu4145.PrivateKey{Curve: dstu4145.ParamsByName("DSTU_PB_173").Curve, D: big.NewInt(1)}
			raw, err := MarshalRawKey(key)
			require.NoError(t, err)
			var info privateKeyInfo
			_, err = asn1.Unmarshal(raw, &info)
			require.NoError(t, err)
			onb := asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 2, 2, index}
			params, err := asn1.Marshal(struct{ Curve asn1.ObjectIdentifier }{onb})
			require.NoError(t, err)
			info.Algorithm.Parameters = asn1.RawValue{FullBytes: params}
			encoded, err := asn1.Marshal(info)
			require.NoError(t, err)
			parsed, err := ParseRawKey(encoded)
			require.Error(t, err)
			require.Nil(t, parsed)
			guessed, err := Parse(encoded, "")
			require.Error(t, err)
			require.Nil(t, guessed)
		})
	}
}
