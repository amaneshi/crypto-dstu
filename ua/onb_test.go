package ua

import (
	"bytes"
	"encoding/asn1"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/keystore"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

func TestONBApplicationRoundtrip(t *testing.T) {
	for _, name := range []string{"DSTU_ONB_173", "DSTU_ONB_179", "DSTU_ONB_191", "DSTU_ONB_233", "DSTU_ONB_431"} {
		t.Run(name, func(t *testing.T) {
			key, err := dstu4145.GenerateKey(dstu4145.ParamsByName(name).Curve)
			require.NoError(t, err)
			certificate := testiit.Certificate(t, key, false)
			info, err := GetCertInfo(certificate.Raw)
			require.NoError(t, err)
			require.Equal(t, name, info.CurveName)
			raw, err := keystore.MarshalRawKey(key)
			require.NoError(t, err)
			pfx, err := ProtectPKCS12(raw, [][]byte{certificate.Raw}, "disposable-onb")
			require.NoError(t, err)
			box := NewBox()
			require.NoError(t, box.LoadKey(pfx, "disposable-onb"))
			require.True(t, box.keys[0].privateKey.Curve.EqualDomain(key.Curve))
			require.Empty(t, box.caCerts)
			message := []byte("ONB application fixture\x00\xff\r\n")
			signed, err := box.SignDocument(message, SignOptions{NoTax: true})
			require.NoError(t, err)
			_, err = box.UnsignDocument(signed)
			require.Error(t, err, "embedded certificate is not trust")
			require.NoError(t, box.LoadCABundle(certificate.Raw))
			result, err := box.UnsignDocument(signed)
			require.NoError(t, err)
			require.Equal(t, message, result.Content)
			for _, static := range []bool{false, true} {
				encrypted, err := box.EncryptDocumentWithOptions(message, certificate.Raw, EncryptionOptions{StaticOriginator: static})
				require.NoError(t, err)
				decrypted, err := box.DecryptDocument(encrypted)
				require.NoError(t, err)
				require.Equal(t, message, decrypted)
				if !static {
					onbOID, err := asn1.Marshal(dstu4145.OIDDstu4145ONBWithGost34311)
					require.NoError(t, err)
					pbOID, err := asn1.Marshal(dstu4145.OIDDstu4145WithGost34311)
					require.NoError(t, err)
					tampered := bytes.Replace(encrypted, onbOID, pbOID, 1)
					require.NotEqual(t, encrypted, tampered)
					plaintext, err := box.DecryptDocument(tampered)
					require.ErrorContains(t, err, "basis differ")
					require.Nil(t, plaintext)
				}
			}
			// Unknown modern ONB wire profiles must not inherit PB identifiers.
			out, err := box.SignDocument(message, SignOptions{NoTax: true, DigestAlgorithm: oid.Kupyna256})
			require.Error(t, err)
			require.Nil(t, out)
			out, err = box.EncryptDocumentWithOptions(message, certificate.Raw, EncryptionOptions{Algorithm: EncryptionKalyna256CFB})
			require.Error(t, err)
			require.Nil(t, out)
		})
	}
}
