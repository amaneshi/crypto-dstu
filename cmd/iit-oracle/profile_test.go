package main

import (
	"bytes"
	"encoding/asn1"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNativeSigningProfileRejectsDowngrades(t *testing.T) {
	directory := filepath.Join("..", "..", "internal", "interop", "testdata", "iit-kupyna512")
	for _, mode := range []string{"attached", "detached"} {
		t.Run(mode, func(t *testing.T) {
			der, err := os.ReadFile(filepath.Join(directory, mode+".cms"))
			require.NoError(t, err)
			detached := mode == "detached"
			require.NoError(t, checkNativeSigningProfile(der, "kupyna512", detached))
			require.Error(t, checkNativeSigningProfile(der, "kupyna256", detached))
			require.Error(t, checkNativeSigningProfile(der, "unknown", detached))
			require.Error(t, checkNativeSigningProfile(der, "kupyna512", !detached))
			require.Error(t, checkNativeSigningProfile(append(bytes.Clone(der), 0), "kupyna512", detached))
			original, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 2, 2, 3})
			require.NoError(t, err)
			replacement, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 2, 2, 1})
			require.NoError(t, err)
			require.Contains(t, string(der), string(original))
			changed := bytes.Replace(der, original, replacement, 1)
			require.Error(t, checkNativeSigningProfile(changed, "kupyna512", detached), "container and signer digests must agree")
			original, err = asn1.Marshal(asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 6, 3, 1})
			require.NoError(t, err)
			replacement, err = asn1.Marshal(asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 6, 1, 1})
			require.NoError(t, err)
			require.Contains(t, string(der), string(original))
			changed = bytes.ReplaceAll(der, original, replacement)
			require.Error(t, checkNativeSigningProfile(changed, "kupyna512", detached), "signature profile must match digest")
		})
	}
	require.Error(t, checkNativeSigningProfile([]byte{0x30, 0}, "kupyna512", false))
}
