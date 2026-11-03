package cert_test

import (
	"bytes"
	"encoding/pem"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/testpki"
	"github.com/stretchr/testify/require"
)

func FuzzParseCertificates(f *testing.F) {
	seed, _ := testpki.Issue(f, "Disposable certificate fuzz seed", nil, nil, nil)
	f.Add(seed.Raw)
	f.Add(append(bytes.Clone(seed.Raw), seed.Raw...))
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: seed.Raw})
	f.Add(encoded)
	f.Add(append(bytes.Clone(encoded), encoded...))
	f.Add([]byte{})
	f.Add([]byte{0x30, 0})
	f.Add([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		original := bytes.Clone(data)
		certificates, err := cert.ParseCertificates(data)
		require.Equal(t, original, data, "parsing changed the caller's input")
		if err != nil {
			require.Nil(t, certificates, "failed bundle parsing released certificates")
			return
		}
		var der []byte
		for _, certificate := range certificates {
			require.NotNil(t, certificate)
			// Unknown/non-DSTU algorithms are intentionally retained as discovery
			// certificates with no usable DSTU public key, not authenticated keys.
			if certificate.PublicKey != nil {
				require.NotNil(t, certificate.PublicKey.Curve)
				require.NotNil(t, certificate.PublicKey.Q)
			}
			parsed, err := cert.ParseCertificate(certificate.Raw)
			require.NoError(t, err)
			require.Equal(t, certificate.Raw, parsed.Raw)
			der = append(der, certificate.Raw...)
		}
		if len(certificates) == 0 {
			return
		}
		// A valid prefix followed by malformed DER must not release the prefix.
		partial, err := cert.ParseCertificates(append(der, 0))
		require.Error(t, err)
		require.Nil(t, partial)
	})
}
