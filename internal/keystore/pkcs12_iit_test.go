//go:build integration

package keystore

import (
	"encoding/asn1"
	"strings"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/stretchr/testify/require"
)

func TestIITPKCS12Integrity(t *testing.T) {
	for _, family := range []string{"gost34311", "kupyna"} {
		t.Run(family, func(t *testing.T) {
			password := "disposable-integrity-test"
			if family == "kupyna" {
				password = strings.Repeat("K", 32)
			}
			generated := testiit.Invoke(t, testiit.Request{Operation: "generate", KeyBits: 257, KeyFamily: family, Password: password})
			require.True(t, generated.OK, generated.Error)
			var pfx pfxASN
			_, err := asn1.Unmarshal(generated.Data, &pfx)
			require.NoError(t, err)
			var mac pkcs12MacData
			_, err = asn1.Unmarshal(pfx.MacData.FullBytes, &mac)
			require.NoError(t, err)
			t.Logf("IIT PFX MAC algorithm=%s; iterations=%d; digest length=%d", mac.MAC.Algorithm.Algorithm, mac.Iterations, len(mac.MAC.Digest))
			pairs, err := ParsePKCS12(generated.Data, password)
			require.NoError(t, err)
			require.Len(t, pairs, 1)
			pairs, err = ParsePKCS12(generated.Data, "wrong password")
			require.ErrorIs(t, err, ErrPKCS12Integrity)
			require.Nil(t, pairs)
			pfx.AuthSafe.Content.Bytes[len(pfx.AuthSafe.Content.Bytes)-1] ^= 1
			altered, err := asn1.Marshal(pfx)
			require.NoError(t, err)
			pairs, err = ParsePKCS12(altered, password)
			require.ErrorIs(t, err, ErrPKCS12Integrity)
			require.Nil(t, pairs)
		})
	}
}
