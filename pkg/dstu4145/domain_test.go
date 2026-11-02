package dstu4145

import (
	"encoding/asn1"
	"encoding/hex"
	"testing"
)

// Public PB257 parameters shared by the CZO example and IIT's generated PKCS#8.
const pb257Parameters = "3081b9307530070202010102010c020100042110bee3db6aea9e1f86578c45c12594ff942394a7d738f9187e6515017294f4ce01022100800000000000000000000000000000006759213af182e987d3e17714907d470d0421b60fd2d8dce8a93423c6101bca91c47a007e6c300b26cd556c9b0e7d20ef292a000440a9d6eb45f13c708280c4967b231f5eadf658eba4c037291d38d96bf025ca4e17f8e9720dc615b43a28975f0bc1dea36438b564ea2c179fd0123e6db8fac57904"

func TestParamsFromDERExplicit(t *testing.T) {
	der, err := hex.DecodeString(pb257Parameters)
	if err != nil {
		t.Fatal(err)
	}
	p := ParamsFromDER(der)
	if p == nil || !p.OID.Equal(OIDCurvePB257) {
		t.Fatal("did not identify the public PB257 parameters")
	}
	// Changing any part of the curve must not select a built-in curve merely by m.
	for _, tc := range []struct {
		name   string
		offset int
	}{
		{"polynomial", 16}, {"a", 19}, {"b", 25}, {"order", 73}, {"base", 108},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := append([]byte(nil), der...)
			changed[tc.offset] ^= 1
			if ParamsFromDER(changed) != nil {
				t.Fatal("accepted changed explicit parameters")
			}
		})
	}
}

func TestParamsFromDERNamed(t *testing.T) {
	for _, p := range AllParams() {
		t.Run(p.Name, func(t *testing.T) {
			der, err := asn1.Marshal(struct{ Curve asn1.ObjectIdentifier }{p.OID})
			if err != nil {
				t.Fatal(err)
			}
			got := ParamsFromDER(der)
			if got == nil || !got.OID.Equal(p.OID) {
				t.Fatal("named parameters did not resolve")
			}
			if ParamsFromDER(append(der, 0)) != nil {
				t.Fatal("accepted trailing parameter data")
			}
		})
	}
}
