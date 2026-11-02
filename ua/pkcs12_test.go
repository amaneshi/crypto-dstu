package ua

import (
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/keystore"
	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/stretchr/testify/require"
)

func TestProtectAndExportPKCS12(t *testing.T) {
	box := NewBox()
	for i := range 2 {
		key := mustGenerateKey(t)
		raw, err := keystore.MarshalRawKey(key)
		require.NoError(t, err)
		certificate := testiit.Certificate(t, key, false)
		// Exercise the public PEM inputs as well as DER.
		if i == 1 {
			raw = keystore.EncodePEM(raw, "PRIVATE KEY")
		}
		data, err := ProtectPKCS12(raw, [][]byte{keystore.EncodePEM(certificate.Raw, "CERTIFICATE")}, "пароль")
		require.NoError(t, err)
		require.NoError(t, box.LoadKey(data, "пароль"))
		require.Equal(t, key.D, box.keys[i].privateKey.D)
	}
	data, err := box.ExportPKCS12("new-password")
	require.NoError(t, err)
	loaded := NewBox()
	require.NoError(t, loaded.LoadKey(data, "new-password"))
	require.Len(t, loaded.keys, 2)
	require.Len(t, loaded.Certificates(), 2)
	require.Empty(t, loaded.caCerts, "embedded certificates must never establish trust")
	for i := range box.keys {
		require.Equal(t, box.keys[i].privateKey.D, loaded.keys[i].privateKey.D)
	}
	_, err = box.ExportPKCS12("")
	require.Error(t, err)
	_, err = (*Box)(nil).ExportPKCS12("public")
	require.Error(t, err)
	_, err = NewBox().ExportPKCS12("public")
	require.Error(t, err)
	keyOnly := NewBox()
	raw, err := keystore.MarshalRawKey(mustGenerateKey(t))
	require.NoError(t, err)
	require.NoError(t, keyOnly.LoadKey(raw, ""))
	_, err = keyOnly.ExportPKCS12("public")
	require.Error(t, err)
}
