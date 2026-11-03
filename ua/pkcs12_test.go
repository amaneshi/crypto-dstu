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

func TestPKCS12UnicodePublicAPI(t *testing.T) {
	key := mustGenerateKey(t)
	raw, err := keystore.MarshalRawKey(key)
	require.NoError(t, err)
	certificate := testiit.Certificate(t, key, false)
	options := PKCS12ExportOptions{Integrity: PKCS12IntegrityPBMAC1SHA256}
	data, err := ProtectPKCS12WithOptions(raw, [][]byte{certificate.Raw}, "密碼😀", options)
	require.NoError(t, err)
	box := NewBox()
	require.NoError(t, box.LoadKey(data, "密碼😀"))
	require.Equal(t, key.D, box.keys[0].privateKey.D)
	require.Empty(t, box.caCerts)
	exported, err := box.ExportPKCS12WithOptions("🔑пароль", options)
	require.NoError(t, err)
	imported := NewBox()
	require.NoError(t, imported.LoadKey(exported, "🔑пароль"))
	require.Equal(t, key.D, imported.keys[0].privateKey.D)
	require.Empty(t, imported.caCerts)
	failed := NewBox()
	require.Error(t, failed.LoadKey(exported, "🔑Пароль"))
	require.Empty(t, failed.keys)
	require.Empty(t, failed.Certificates())
	data, err = ProtectPKCS12WithOptions(raw, [][]byte{certificate.Raw}, "public", PKCS12ExportOptions{Integrity: "unknown"})
	require.Error(t, err)
	require.Nil(t, data)
	data, err = ProtectPKCS12(raw, [][]byte{certificate.Raw}, "😀")
	require.Error(t, err)
	require.Nil(t, data)
	data, err = (*Box)(nil).ExportPKCS12WithOptions("😀", options)
	require.Error(t, err)
	require.Nil(t, data)
}
