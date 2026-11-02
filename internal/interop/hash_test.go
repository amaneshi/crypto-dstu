//go:build integration

package interop_test

import (
	"encoding/asn1"
	"fmt"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/amaneshi/crypto-dstu/internal/tsp"
	"github.com/stretchr/testify/require"
)

func TestIITNationalHashProfiles(t *testing.T) {
	for _, profile := range []struct {
		name string
		oid  asn1.ObjectIdentifier
	}{
		{"gost34311", oid.GOST34311},
		{"kupyna256", oid.Kupyna256},
		{"kupyna512", oid.Kupyna512},
	} {
		t.Run(profile.name, func(t *testing.T) {
			for _, length := range []int{0, 1, 31, 32, 51, 52, 63, 64, 115, 116, 127, 128, 129, 257} {
				t.Run(fmt.Sprint(length), func(t *testing.T) {
					data := make([]byte, length)
					for i := range data {
						data[i] = byte(i)
					}
					native := testiit.Invoke(t, testiit.Request{Operation: "hash", Digest: profile.name, Data: data})
					require.True(t, native.OK, native.Error)
					got, err := tsp.HashData(data, profile.oid)
					require.NoError(t, err)
					require.Equal(t, native.Data, got)
				})
			}
		})
	}
}
