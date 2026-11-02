package dstu4145

import (
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestONBReferenceParameters(t *testing.T) {
	data, err := os.ReadFile("testdata/onb-cryptonite.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Source  string
		Vectors []struct{ Name, OID, ParametersHex string }
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Vectors) != 5 || fixture.Source == "" {
		t.Fatal("missing independent ONB fixture provenance")
	}
	for _, v := range fixture.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			parameters, err := hex.DecodeString(v.ParametersHex)
			if err != nil {
				t.Fatal(err)
			}
			wrapped, err := asn1.Marshal(struct{ Curve asn1.RawValue }{asn1.RawValue{FullBytes: parameters}})
			if err != nil {
				t.Fatal(err)
			}
			resolved := ParamsFromDER(wrapped)
			if resolved == nil || !resolved.Curve.IsONB() {
				t.Fatal("independent ONB parameters did not resolve")
			}
			var oid asn1.ObjectIdentifier
			for _, part := range strings.Split(v.OID, ".") {
				n, err := strconv.Atoi(part)
				if err != nil {
					t.Fatal(err)
				}
				oid = append(oid, n)
			}
			if ParamsByOID(oid) == nil || !resolved.OID.Equal(oid) {
				t.Fatal("ONB named and explicit domains differ")
			}
			named, err := asn1.Marshal(struct{ Curve asn1.ObjectIdentifier }{oid})
			if err != nil {
				t.Fatal(err)
			}
			if ParamsFromDER(named) != resolved {
				t.Fatal("ONB named parameters did not resolve")
			}
			wrapped[len(wrapped)-1] ^= 2
			if ParamsFromDER(wrapped) != nil {
				t.Fatal("altered ONB domain accepted")
			}
		})
	}
}
